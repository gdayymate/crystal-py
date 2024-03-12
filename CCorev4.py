import hashlib
import datetime
from transactions import Transaction
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from rusty import calculate_stem_hash
import os
from time import perf_counter
import logging

from config import SEED_LENGTH, DIFFICULTY, EPOCHS, NUM_PRODUCERS

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        except ValueError as e:
            logging.error(f"Error verifying signature: {e}")
            return False

    def add_neighbors(self, fruit, blockchain):
        if self.verify_signatures(fruit) and blockchain.is_producer_enlisted(blockchain.current_epoch, fruit.pk):
            self.neighbors.append(fruit)
        else:
            logging.warning(f"Invalid signature or not eligible for the current epoch from {fruit.pk}")

    def update_prev_stem(self, new_stem):   
        self.prev_stem = new_stem

    def sign_data(self, private_key):
        message = f"{self.timestamp}{self.data}".encode()
        try:
            signature = private_key.sign(message)
            return signature
        except Exception as e:
            logging.error(f"Error signing data: {e}")
            return None

    def verify(self, fruit, current_epoch, blockchain, public_key):
        try:
            public_key.verify(self.signature, self.data.encode())
            if fruit.pk not in blockchain.enlisted_producers.get(current_epoch, []):
                raise ValueError("Public key not assigned to this epoch")
            return True
        except ValueError as e:
            logging.error(f"Error verifying fruit: {e}")
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
        self.merkle_root = None

    def add_fruit_and_update_merkle_tree(self, fruit, blockchain):
        if fruit.hash not in self.fruits_digest and fruit.verify(fruit, blockchain.current_epoch, blockchain, fruit.pk):
            self.fruits.append(fruit)
            self.update_merkle_tree()
            logging.info(f"Added fruit {fruit.hash} to the stem")
            blockchain.enlist_producer(fruit.pk)  # Re-enlist the producer
        else:
            logging.warning("Fruit producer is not enlisted for this epoch.")

    def update_merkle_tree(self):
        self.fruits.sort(key=lambda x: x.hash)
        merkle_leaves = [fruit.hash for fruit in self.fruits]
        self.merkle_root = self.calculate_merkle_root(merkle_leaves)

    def calculate_merkle_root(self, leaves):
        if not leaves:
            return None

        if len(leaves) == 1:
            return leaves[0]

        new_leaves = []
        for i in range(0, len(leaves), 2):
            left = leaves[i]
            right = leaves[i + 1] if i + 1 < len(leaves) else left
            combined_hash = hashlib.sha256(f"{left}{right}".encode()).hexdigest()
            new_leaves.append(combined_hash)

        return self.calculate_merkle_root(new_leaves)

    def calculate_hash(self):
        try:
            rust_result, self.nonce = calculate_stem_hash(
                int(self.timestamp.timestamp()),
                f"{self.data}{self.timestamp}{self.tip if self.tip else ''}".encode('utf-8'),
                [fruit.data for fruit in self.fruits],
                self.hash,
                int(self.nonce or 0)
            )
            if self.difficulty >= 100 * Stem.BASE_DIFFICULTY:
                logging.info("New Leaf Found!")
                return rust_result, True  # Return a flag indicating a new leaf
            return rust_result, False
        except Exception as e:
            logging.error(f"Error calculating stem hash: {e}")
            return None, False

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
        new_hash, is_new_leaf = new_stem.calculate_hash()
        if is_new_leaf:
            new_leaf = Leaf(new_stem.data, new_stem.difficulty, new_hash, new_stem.previous_hash)
            for fruit in self.get_all_fruits():
                fruit.update_prev_stem(new_stem)
            self.extend_branch(new_leaf)
        else:
            self.chain.append(new_stem)
            self.most_recent_stem = new_stem
            logging.info(f"Added new stem with difficulty {new_stem.difficulty}")

    def extend_branch(self, new_leaf):
        if isinstance(new_leaf, Leaf):
            if self.is_valid_leaf(new_leaf):
                last_block = self.get_last_block()
                if last_block:
                    new_leaf.previous_hash = last_block.hash
                else:
                    logging.warning("No blocks in the chain. Ensure a genesis block is created first.")
                    return False
                self.chain.append(new_leaf)
                self.start_next_epoch()
                self.update_dag(last_block, new_leaf)
                for fruit in new_leaf.fruits:
                    new_leaf.fruits_digest.add(fruit.hash)
                if new_leaf.previous_hash:
                    prev_leaf = self.get_leaf_by_hash(new_leaf.previous_hash)
                    if prev_leaf:
                        self.enlist_producer(prev_leaf.public_key)
                logging.info(f"Added new leaf with hash {new_leaf.hash}")
                return True
            else:
                logging.warning("New leaf is not valid.")
                return False
        else:
            logging.warning("Invalid block type. Expected a Leaf instance.")
            return False

    def is_valid_leaf(self, leaf):
        if not leaf.verify():
            logging.warning("Invalid leaf block signature.")
            return False
        last_block = self.get_last_block()
        if last_block.hash != leaf.previous_hash:
            logging.warning("Invalid leaf block. Previous hash mismatch.")
            return False
        return True

    def get_last_block(self):
        for block in reversed(self.chain):
            if isinstance(block, Leaf):
                return block
        return None

    def enlist_producer(self, public_key, max_epochs=3):
        if self.current_epoch + 1 not in self.enlisted_producers:
            self.enlisted_producers[self.current_epoch + 1] = {public_key: max_epochs}
            logging.info(f"Enlisted producer {public_key} for epoch {self.current_epoch + 1}")
        elif public_key in self.enlisted_producers[self.current_epoch + 1]:
            self.enlisted_producers[self.current_epoch + 1][public_key] = max_epochs  # Reset the max_epochs count
            logging.info(f"Re-enlisted producer {public_key} for epoch {self.current_epoch + 1}")
        else:
            self.enlisted_producers[self.current_epoch + 1][public_key] = max_epochs
            logging.info(f"Enlisted producer {public_key} for epoch {self.current_epoch + 1}")

    def is_producer_enlisted(self, epoch, public_key):
        """Checks if a producer is enlisted for a given epoch."""
        return public_key in self.enlisted_producers.get(epoch, [])       

    def get_leaf_by_hash(self, hash):
        for block in reversed(self.chain):
            if isinstance(block, Leaf) and block.hash == hash:
                return block
        return None

    def start_next_epoch(self):
        self.current_epoch += 1
        logging.info(f"Starting epoch {self.current_epoch}")

    def update_dag(self, last_block, new_leaf):
        # Update DAG logic here
        pass

    def get_all_fruits(self):
        fruits = []
        for block in self.chain:
            if isinstance(block, Stem):
                fruits.extend(block.fruits)
        return fruits
