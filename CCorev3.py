import hashlib
import datetime
from transactions import Transaction
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from rusty import mine_for_nonce_range
import os
from time import perf_counter

def generate_seed():
   return int((os.urandom(8) + str(perf_counter()).encode('utf-8')).hex())


class Fruit:
   def __init__(self, data, neighbors, public_key, private_key, epoch_public):
       self.timestamp = datetime.datetime.now()
       self.seed = generate_seed()
       self.data = f"{data}-{self.seed}"
       self.tip = None
       self.neighbors = neighbors
       self.signature = self.sign_data(private_key)
       self.hash = self.calculate_hash()
       self.epoch = epoch_public

   def calculate_hash(self):
       data_to_hash = f"{self.data}{self.timestamp}{self.seed}{self.tip if self.tip else ''}"
       return hashlib.sha256(data_to_hash.encode()).hexdigest()

   def sign_data(self, private_key):
       message = self.data.encode()
       signature = private_key.sign(message)
       return signature

   def verify(self, public_key):
       try:
           public_key.verify(self.signature, self.data.encode())

           # Check if this fruit is assigned to the current epoch
           if public_key.to_string().hex() not in self.epoch_public_keys:
               raise ValueError("Public key not assigned to this epoch")

           return True
       except ValueError:
           return False

   def most_recent_leaf(self, blockchain):
       """Update the tip to the hash of the most recent Leaf block."""
       # Assuming get_last_leaf_block() returns the most recent Leaf block
       most_recent_leaf = blockchain.get_last_leaf_block()
       if most_recent_leaf:
           self.tip = most_recent_leaf.hash
           self.hash = self.calculate_hash()
       
def merkle_root(transactions):
   if len(transactions) == 1:
       return transactions[0].hash

   tx_pairs = [(t1, t2) for t1, t2 in zip(transactions[::2], transactions[1::2])]
   next_level = [hashlib.sha256(f"{tx1.hash}{tx2.hash}".encode()).hexdigest() for tx1, tx2 in tx_pairs]
   odd_tx = transactions[-1] if len(transactions) % 2 != 0 else None

   if odd_tx:
       next_level.append(odd_tx.hash)

   return merkle_root(next_level)

class Stem:
   def __init__(self, data, difficulty):
       self.timestamp = datetime.now()
       self.data = data
       self.difficulty = difficulty
       self.nonce = None
       self.hash = None
       self.fruits_digest = set()
       self.fruits = []

   def add_fruit(self, fruit, blockchain):
        if fruit.hash not in self.fruits_digest and fruit.verify():
            # Check if the fruit producer is enlisted for the current epoch
            current_epoch = blockchain.current_epoch
            if fruit.public_key in blockchain.enlisted_producers.get(current_epoch, []):
                self.fruits.append(fruit)
            else:
                print("Fruit producer is not enlisted for this epoch.")

   def verify(self, fruit):
       try:
           public_key = VerifyingKey.from_string(bytes.fromhex(fruit.public_key), curve=SECP256k1)
           public_key.verify(fruit.signature, fruit.data.encode(), hashfunc=hashlib.sha256)
           return True
       except ValueError:
           return False

   def calculate_hash(self):
       merkle_tree = merkle_root([fruit.hash for fruit in self.fruits])
       data_to_hash = f"{self.data}{self.timestamp}{merkle_tree}{self.tip if self.tip else ''}"
       return hashlib.sha256(data_to_hash.encode()).hexdigest()

   def mine_block(self):
       while True:
           input_data = self.hash
           fruit_data = ''.join([fruit.data for fruit in self.fruits])
           nonce = mine_for_nonce_range((input_data + fruit_data).encode(), self.difficulty)

           if nonce is not None:
               break

           print("Mining failed, retrying...")

       self.nonce = nonce
       self.hash = self.calculate_hash()
       self.digest |= {fruit.hash for fruit in self.active_list}
       self.fruits = []
    
class Leaf(Stem):
   def __init__(self, data, public_key, difficulty):
       super().__init__(data, public_key, difficulty * 100)

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()
        self.enlisted_producers = {}  # Dictionary to track enlisted producers per epoch
        self.current_epoch =  0  # Variable to track the current epoch


    def create_genesis_block(self):
        """Create the first block of the chain."""
        genesis_block = Leaf("Genesis Block", "0",  1)  # Assuming Leaf is the correct starting block type
        genesis_block.previous_hash = "0"
        genesis_block.mine_block()
        self.chain.append(genesis_block)

    def add_block(self, new_block):
       """Add a new block to the chain if it's valid."""
       if not self.is_valid_block(new_block):
           return False

       # Check for double spending
       spent_outputs = set()
       for tx in new_block.transactions:
           if any(input.id in spent_outputs for input in tx.inputs):
               return False

           spent_outputs |= {output.id for output in tx.outputs}

       # Validate transaction signatures
       for tx in new_block.transactions:
           if not tx.verify():
               return False

       self.chain.append(new_block)
       return True

    def is_valid_block(self, block):
        """Validate a block."""
        last_block = self.get_last_block()
        if last_block.hash != block.previous_hash:
            return False
        # Additional validation checks can be implemented here
        # For example, verify the block's hash, check for duplicate transactions, etc.
        return True


    def get_last_leaf_block(self):
        """Retrieve the most recent Leaf block in the chain."""
        for block in reversed(self.chain):
                if isinstance(block, Leaf):
                    return block
        return None

    def extend_branch(self, new_leaf):
        """Extend the block-tree with a new leaf."""
        if isinstance(new_leaf, Leaf):
            # Ensure the new leaf is valid and extends the chain correctly
            if self.is_valid_block(new_leaf):
                self.chain.append(new_leaf)
                # Assuming you have a method to update the DAG, ensure it's called here
                self.update_dag(self.get_last_block(), new_leaf)
                # Move active Fruits to the digest_list after mining
                for fruit in new_leaf.fruits:
                    # Assuming digest_list is correctly defined and used
                    new_leaf.digest_list.add(fruit.hash)
                return True
            else:
                print("New leaf is not valid.")
                return False
        else:
            print("Provided object is not a Leaf instance.")
            return False
        
    def start_new_epoch(self):
        self.current_epoch +=  1
        self.enlisted_producers[self.current_epoch] = []

    def enlist_producer(self, public_key):
        self.enlisted_producers[self.current_epoch].append(public_key)