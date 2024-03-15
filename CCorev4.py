import hashlib
import datetime
from transactions import Transaction
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from StemHasherv3 import calculate_stem_hash
import os
from time import perf_counter
import logging

from config import DIFFICULTY, LEAF_DIFFICULTY_THRESHOLD, INITIAL_COMMITTEE, EPOCHS

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

    def verify(self, blockchain, public_key):
        try:
            public_key.verify(self.signature, self.data.encode())
            if self.pk not in blockchain.enlisted_producers.get(self.epoch, {}):
                raise ValueError("Public key not assigned to this epoch")
            return True
        except (ValueError, KeyError) as e:
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
        if fruit.hash not in self.fruits_digest and fruit.verify(blockchain, fruit.pk):
            self.fruits.append(fruit)
            self.update_merkle_tree()
            logging.info(f"Added fruit {fruit.hash} to the stem")
            blockchain.enlist_producer(fruit.pk)  # Re-enlist the producer
            return True
        else:
            logging.warning("Fruit verification failed or fruit already exists in the stem.")
            return False

    def update_merkle_tree(self):
        self.fruits.sort(key=lambda x: x.hash)
        merkle_leaves = [fruit.hash for fruit in self.fruits]
        self.merkle_root = self.calculate_merkle_root(merkle_leaves)

    def calculate_merkle_root(self, leaves):
        if not leaves:
            return None

        while len(leaves) > 1:
            if len(leaves) % 2 != 0:
                leaves.append(leaves[-1])  # Duplicate the last leaf if the number of leaves is odd
            new_leaves = []
            for i in range(0, len(leaves), 2):
                left = leaves[i]
                right = leaves[i + 1]
                combined_hash = hashlib.sha256(f"{left}{right}".encode()).hexdigest()
                new_leaves.append(combined_hash)
            leaves = new_leaves

        return leaves[0]

    def calculate_hash(self):
        try:
            rust_result, self.nonce, is_leaf = calculate_stem_hash(
                int(self.timestamp.timestamp()),
                self.data.encode('utf-8'),
                [fruit.data.encode('utf-8') for fruit in self.fruits],
                self.hash,
                int(self.nonce or 0),
                DIFFICULTY,
                LEAF_DIFFICULTY_THRESHOLD
            )
            self.hash = rust_result
            if is_leaf:
                logging.info("New Leaf Found!")
                return rust_result, True  # Return a flag indicating a new leaf
            return rust_result, False
        except Exception as e:
            logging.error(f"Error calculating stem hash: {e}")
            return None, False

    def is_valid_stem(self):
        # Check if the stem hash meets the required difficulty
        if not self.hash.startswith('1' * DIFFICULTY):
            return False
        return True


class Leaf(Stem):
    def __init__(self, data, difficulty, rust_result, previous_hash):
        super().__init__(data, difficulty, rust_result, previous_hash)

    def is_valid_leaf(self):
        # Check if the leaf hash meets the required leaf difficulty
        if not self.hash.startswith('1' * LEAF_DIFFICULTY_THRESHOLD):
            return False
        return True

class Blockchain:
    def __init__(self):
        self.chain = []
        self.enlisted_producers = {0: {pk: float('inf') for pk in INITIAL_COMMITTEE}}
        self.current_epoch = 0
        self.most_recent_leaf = None
        self.most_recent_stem = None

    def add_stem(self, new_stem):
        new_hash, is_new_leaf = new_stem.calculate_hash()
        if is_new_leaf:
            new_leaf = Leaf(new_stem.data, new_stem.difficulty, new_hash, new_stem.previous_hash)
            if new_leaf.is_valid_leaf():
                self.extend_branch(new_leaf)
                self.most_recent_leaf = new_leaf  # Update the most recent leaf
            else:
                logging.warning("Invalid leaf hash. Leaf not added to the chain.")
        else:
            if new_stem.is_valid_stem():
                self.chain.append(new_stem)
                self.most_recent_stem = new_stem
                logging.info(f"Added new stem with difficulty {new_stem.difficulty}")
            else:
                logging.warning("Invalid stem hash. Stem not added to the chain.")

    def extend_branch(self, new_leaf):
        if isinstance(new_leaf, Leaf):
            last_block = self.get_last_leaf()
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
                self.enlist_producer(fruit.pk, self.current_epoch)  # Pass the current epoch as the last contribution epoch
            logging.info(f"Added new leaf with hash {new_leaf.hash}")
            return True
        else:
            logging.warning("Invalid block type. Expected a Leaf instance.")
            return False

    def get_last_leaf(self):
        for block in reversed(self.chain):
            if isinstance(block, Leaf):
                return block
        return None


    def enlist_producer(self, public_key, last_contribution_epoch):
        if self.current_epoch + 1 not in self.enlisted_producers:
            self.enlisted_producers[self.current_epoch + 1] = {}
        if public_key in self.enlisted_producers[self.current_epoch + 1]:
            if last_contribution_epoch > self.enlisted_producers[self.current_epoch + 1][public_key]['last_contribution']:
                self.enlisted_producers[self.current_epoch + 1][public_key]['last_contribution'] = last_contribution_epoch
                logging.info(f"Updated last contribution for producer {public_key} in epoch {self.current_epoch + 1}")
        else:
            if self.current_epoch - last_contribution_epoch <= 1:
                self.enlisted_producers[self.current_epoch + 1][public_key] = {'last_contribution': last_contribution_epoch}
                logging.info(f"Enlisted producer {public_key} for epoch {self.current_epoch + 1}")

    def reconfigure_committee(self, new_committee):
        self.enlisted_producers[self.current_epoch + 1] = {pk: float('inf') for pk in new_committee}
        logging.info(f"Reconfigured committee for epoch {self.current_epoch + 1}: {new_committee}")


    def is_producer_enlisted(self, epoch, public_key):
        """Checks if a producer is enlisted for a given epoch."""
        return public_key in self.enlisted_producers.get(epoch, {})

    def get_leaf_by_hash(self, hash):
        for block in reversed(self.chain):
            if isinstance(block, Leaf) and block.hash == hash:
                return block
        return None

    def start_next_epoch(self):
        self.current_epoch += 1
        logging.info(f"Starting epoch {self.current_epoch}")
        
        if self.current_epoch - 2 in self.enlisted_producers:
         inactive_members = [
            pk for pk, data in self.enlisted_producers[self.current_epoch - 2].items()
            if data['last_contribution'] < self.current_epoch - 2
        ]
        for pk in inactive_members:
            del self.enlisted_producers[self.current_epoch - 2][pk]
            logging.info(f"Removed inactive committee member {pk} from epoch {self.current_epoch - 2}")

    def update_dag(self, last_block, new_leaf):
        # Update DAG logic here
        pass

    def get_all_fruits(self):
        fruits = []
        for block in self.chain:
            if isinstance(block, Stem):
                fruits.extend(block.fruits)
        return fruits
