import hashlib
import datetime
from transactions import Transaction
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from rusty import calculate_stem_hash
import os
import EpochLogic
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

  def check_signatures(self, fruit):
      if self.verify_signatures(fruit):
          self.neighbors.append(fruit)
      else:
          print(f"Invalid signature from {fruit.public_key}")



  def sign_data(self, private_key):
      message = self.data.encode()
      signature = private_key.sign(message)
      return signature

  def verify(self, fruit, current_epoch, blockchain, public_key):
      try:
          public_key.verify(self.signature, self.data.encode())

          # Check if this fruit is assigned to the current epoch
          if fruit.public_key not in blockchain.enlisted_producers.get(current_epoch, []):
            self.fruits.append(fruit)
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
    
  def calculate_hash(self):
    data_to_hash = f"{self.data}{self.timestamp}{self.seed}{self.pk.to_string().hex()}{self.tip if self.tip else ''}"
    return hashlib.sha256(data_to_hash.encode()).hexdigest()

class Stem:
  BASE_DIFFICULTY = 1  # You can adjust the base difficulty as needed
  def __init__(self, data, difficulty, rust_result, previous_hash):
       self.timestamp = datetime.now()
       self.data = data
       self.difficulty = Stem.BASE_DIFFICULTY
       self.nonce = None       
       self.tip = Leaf
       self.hash = rust_result()
       self.fruits_digest = set()
       self.fruits = []

  def add_fruit(self, fruit, blockchain):
     if fruit.hash not in self.fruits_digest and fruit.verify():
  # Check if the fruit producer is enlisted for the current epoch
        current_epoch = blockchain.current_epoch
     if fruit.public_key in blockchain.enlisted_producers.get(current_epoch, []):
            self.fruits.append(fruit)
     # Update the merkle tree after adding a new fruit
            self.update_merkle_tree()
     else:
        print("Fruit producer is not enlisted for this epoch.")

  def update_merkle_tree(self):
 # Sort the list of fruits based on their hash values in ascending order
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
        # Assuming calculate_stem_hash is a Rust function with appropriate bindings
        rust_result, self.nonce = calculate_stem_hash(
            int(self.timestamp.timestamp()),
            f"{self.data}{self.timestamp}{self.tip if self.tip else ''}".encode('utf-8'),
            [fruit.data for fruit in self.fruits],  # Use fruit.data instead of fruit[0].data
            self.hash,
            int(self.nonce or 0)
        )

        # Check if the calculated difficulty is significantly higher than the base difficulty
        if self.difficulty >= 100 * Stem.BASE_DIFFICULTY:
            print("New Leaf Found!")

        return rust_result

  
class Leaf(Stem):
    def __init__(self, data, difficulty, rust_result, previous_hash):
        super().__init__(data, difficulty, rust_result, previous_hash)


class Blockchain:
    def __init__(self):
        self.chain = []
        self.enlisted_producers = {}
        self.current_epoch = 0
        self.most_recent_leaf_ = None  # Reference to the most recent Leaf block
        self.most_recent_stem = None # Track the most recent stem

    def add_stem(self, new_stem):
        # Check if the new stem should be considered a Leaf
        if self.most_recent_stem and new_stem.difficulty >= 100 * self.most_recent_stem.difficulty:
            # Convert the new stem to a Leaf
            new_leaf = Leaf(new_stem.data, new_stem.difficulty, new_stem.rust_result, new_stem.previous_hash)
            self.add_leaf(new_leaf)
        else:
            # Add the new stem as a regular stem
            self.chain.append(new_stem)
            self.most_recent_stem = new_stem 

    def create_genesis_block(self):
        genesis_block = Leaf("Genesis Block", "0", 1, 0, self.most_recent_leaf_block)
        genesis_block.mine_block()
        self.chain.append(genesis_block)
        self.most_recent_leaf_block = genesis_block  # Update the reference

    def add_leaf(self, new_leaf):
        if not isinstance(new_leaf, Leaf):
            print("Invalid block type. Expected Leaf.")
            return False

        if not self.is_valid_leaf(new_leaf):
            print("Invalid leaf block.")
            return False

        self.chain.append(new_leaf)
        self.most_recent_leaf_block = new_leaf  # Update the reference
        self.update_dag(self.get_last_block(), new_leaf)

        for fruit in new_leaf.fruits:
            new_leaf.fruits_digest.add(fruit.hash)

        if new_leaf.previous_hash:
            prev_leaf = self.get_leaf_by_hash(new_leaf.previous_hash)
            if prev_leaf:
                self.enlist_producers(prev_leaf.enlisted_producers)

        return True

    def is_valid_leaf(self, leaf):
        if not leaf.verify():
            print("Invalid leaf block signature.")
            return False

        last_block = self.get_last_block()
        if last_block.hash != leaf.previous_hash:
            print("Invalid leaf block. Previous hash mismatch.")
            return False

        # Additional validation checks can be added here

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

   def extend_branch(self, new_leaf):
   """Extend the block-tree with a new leaf."""
   if isinstance(new_leaf, Leaf):
       # Ensure the new leaf is valid and extends the chain correctly
       if self.add_block(new_leaf):
           # Assuming you have a method to update the DAG, ensure it's called here
           self.update_dag(self.get_last_block(), new_leaf)

           # Move active Fruits to the digest_list after mining
           for fruit, _ in new_leaf.fruits:
               # Assuming digest_list is correctly defined and used
               new_leaf.digest_list.add(fruit.hash)

           # Start a new epoch since a new leaf has been mined
           self.start_next_epoch()

           # Enlist valid fruit producers for the next epoch
           for fruit in new_leaf.fruits:
               if fruit.is_valid_signature():
                 self.enlist_producer(fruit.public_key)

           return True
      else:
          print("New leaf is not valid.")
          return False

    def get_leaf_by_hash(self, hash):
        for block in reversed(self.chain):
            if isinstance(block, Leaf) and block.hash == hash:
                return block
        return None
