import hashlib
import datetime
from transactions import Transaction
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from rusty import calculate_stem_hash
import os
from time import perf_counter

from config import SEED_LENGTH, DIFFICULTY, EPOCHS, NUM_PRODUCERS

def generate_seed():
    return int((os.urandom(32) + str(perf_counter()).encode('utf-8')).hex())

class Fruit:
    def __init__(self, data, neighbors, public_key, private_key, current_epoch):
        self.timestamp = datetime.datetime.now()
        self.seed = generate_seed()
        self.pk = public_key
        self.data = f"{data}-{self.seed}"
        self.tip = None
        self.prev_stem = None
        self.neighbors = neighbors
        self.signature = self.sign_data(private_key)
        self.hash = self.calculate_hash()
        self.epoch = current_epoch

    def verify_signatures(self, fruit):
        try:
            verifying_key = VerifyingKey.from_string(bytes.fromhex(fruit.pk), curve=SECP256k1)
            verifying_key.verify(fruit.signature, fruit.data.encode(), hashfunc=hashlib.sha256)
            return True
        except ValueError:
            return False

    def add_neighbors(self, fruit, blockchain):
        if self.verify_signatures(fruit) and blockchain.is_producer_enlisted(blockchain.current_epoch, fruit.pk):
            self.neighbors.append(fruit)
        else:
            print(f"Invalid signature or not eligible for the current epoch from {fruit.pk}")

    def update_prev_stem(self, new_stem):   
        self.prev_stem = new_stem

    def sign_data(self, private_key):
        message = f"{self.timestamp}{self.data}".encode()
        signature = private_key.sign(message)
        return signature

    def verify(self, fruit, current_epoch, blockchain, public_key):
        try:
            public_key.verify(self.signature, self.data.encode())
            if fruit.pk not in blockchain.enlisted_producers.get(current_epoch, []):
                raise ValueError("Public key not assigned to this epoch")
            return True
        except ValueError:
            return False

    def calculate_hash(self):
        data_to_hash = f"{self.data}{self.timestamp}{self.prev_stem}{self.seed}{self.pk.to_string().hex()}{self.tip if self.tip else ''}"
        return hashlib.sha256(data_to_hash.encode()).hexdigest()

class Stem:
    BASE_DIFFICULTY = 1
    def __init__(self, data, difficulty, rust_result, previous_hash):
        self.timestamp = datetime.datetime.now()
        self.data = data
        self.difficulty = Stem.BASE_DIFFICULTY
        self.nonce = None
        self.tip = None
        self.hash = rust_result()
        self.fruits_digest = set()
        self.fruits = []

    def add_fruit(self, fruit, blockchain):
        if fruit.hash not in self.fruits_digest and fruit.verify(fruit, blockchain.current_epoch, blockchain, fruit.pk):
            self.fruits.append(fruit)
            self.update_merkle_tree()
        else:
            print("Fruit producer is not enlisted for this epoch.")

    def update_merkle_tree(self):
        self.fruits.sort(key=lambda x: x.hash)
        while len(self.fruits) > 1:
            next_level = []
            for i in range(0, len(self.fruits), 2):
                fruit1, _ = self.fruits[i]
                fruit2, _ = self.fruits[i + 1] if i + 1 < len(self.fruits) else (None, None)
                combined_hash = hashlib.sha256(f"{fruit1.hash}{fruit2.hash}".encode()).hexdigest() if fruit2 else fruit1.hash
                next_level.append((combined_hash, None))
            self.fruits = next_level

    def calculate_hash(self):
        rust_result, self.nonce = calculate_stem_hash(
            int(self.timestamp.timestamp()),
            f"{self.data}{self.timestamp}{self.tip if self.tip else ''}".encode('utf-8'),
            [fruit.data for fruit in self.fruits],
            self.hash,
            int(self.nonce or 0)
        )
        if self.difficulty >= 100 * Stem.BASE_DIFFICULTY:
            print("New Leaf Found!")
        return rust_result

class Leaf(Stem):
    def __init__(self, data, difficulty, rust_result, previous_hash, signature=None):
        super().__init__(data, difficulty, rust_result, previous_hash)
        self.signature = signature

class Blockchain:
    def __init__(self):
        self.chain = []
        self.enlisted_producers = {}
        self.current_epoch = 0
        self.most_recent_leaf = None
        self.most_recent_stem = None

    def add_stem(self, new_stem):
        if self.most_recent_stem and new_stem.difficulty >= 100 * self.most_recent_stem.difficulty:
            new_leaf = Leaf(new_stem.data, new_stem.difficulty, new_stem.hash, new_stem.previous_hash)
            for fruit in self.get_all_fruits():
                fruit.update_prev_stem(new_stem)
            self.add_leaf(new_leaf)
        else:
            self.chain.append(new_stem)
            self.most_recent_stem = new_stem

    def add_leaf(self, new_leaf):
        if not isinstance(new_leaf, Leaf):
            print("Invalid block type. Expected Leaf.")
            return False
        if not self.is_valid_leaf(new_leaf):
            print("Invalid leaf block.")
            return False
        self.chain.append(new_leaf)
        self.most_recent_leaf = new_leaf
        self.update_dag(self.get_last_block(), new_leaf)
        for fruit in new_leaf.fruits:
            new_leaf.fruits_digest.add(fruit.hash)
        if new_leaf.previous_hash:
            prev_leaf = self.get_leaf_by_hash(new_leaf.previous_hash)
            if prev_leaf:
                self.enlist_producer(prev_leaf.public_key, max_epochs=2)
        return True

    def is_valid_leaf(self, leaf):
        if not leaf.verify():
            print("Invalid leaf block signature.")
            return False
        last_block = self.get_last_block()
        if last_block.hash != leaf.previous_hash:
            print("Invalid leaf block. Previous hash mismatch.")
            return False
        return True

    def get_last_block(self):
        for block in reversed(self.chain):
            if isinstance(block, Leaf):
                return block
        return None

    def enlist_producer(self, public_key, max_epochs=2):
        if self.current_epoch + 1 not in self.enlisted_producers:
            self.enlisted_producers[self.current_epoch + 1] = {public_key: max_epochs}
        elif public_key in self.enlisted_producers[self.current_epoch + 1]:
            self.enlisted_producers[self.current_epoch + 1][public_key] -= 1
            if self.enlisted_producers[self.current_epoch + 1][public_key] == 0:
                del self.enlisted_producers[self.current_epoch + 1][public_key]
        else:
            self.enlisted_producers[self.current_epoch + 1][public_key] = max_epochs

    def is_producer_enlisted(self, epoch, public_key):
        """Checks if a producer is enlisted for a given epoch."""
        return public_key in self.enlisted_producers.get(epoch, [])       


    def extend_branch(self, new_leaf):
        if isinstance(new_leaf, Leaf):
            if self.is_valid_leaf(new_leaf):
                last_block = self.get_last_block()
                if last_block:
                    new_leaf.previous_hash = last_block.hash
                else:
                    print("No blocks in the chain. Ensure a genesis block is created first.")
                    return False
                self.chain.append(new_leaf)
                self.update_dag(last_block, new_leaf)
                for fruit in new_leaf.fruits:
                    new_leaf.fruits_digest.add(fruit.hash)
                if new_leaf.previous_hash:
                    prev_leaf = self.get_leaf_by_hash(new_leaf.previous_hash)
                    if prev_leaf:
                        self.enlist_producer(prev_leaf.public_key, max_epochs=2)
                return True
            else:
                print("New leaf is not valid.")
                return False

    def get_leaf_by_hash(self, hash):
        for block in reversed(self.chain):
            if isinstance(block, Leaf) and block.hash == hash:
                return block
        return None

