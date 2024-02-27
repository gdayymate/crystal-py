import json
from datetime import datetime
from CCorev3 import Fruit, Stem, Leaf

def serialize_datetime(dt):
   return dt.strftime("%Y-%m-%dT%H:%M:%S")

def deserialize_datetime(dt_str):
   return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S")

def serialize_block(block):
   block_data = {
       'timestamp': serialize_datetime(block.timestamp),
       'data': block.data,
       'previous_hash': block.previous_hash,
       'difficulty': block.difficulty,
       'nonce': block.nonce,
       'hash': block.hash,
   }
   if isinstance(block, Stem) or isinstance(block, Leaf):
       block_data['fruits'] = [serialize_fruit(fruit) for fruit in block.fruits]
   return json.dumps(block_data)

def deserialize_block(json_str, block_type):
   data = json.loads(json_str)
   if block_type == "Stem":
       block = Stem(data['data'], None, data['difficulty'])  # Add other necessary parameters
   elif block_type == "Leaf":
       block = Leaf(data['data'], None, data['difficulty'])  # Add other necessary parameters
   else:
       raise ValueError("Invalid block type for deserialization")

   block.timestamp = deserialize_datetime(data['timestamp'])
   block.previous_hash = data['previous_hash']
   block.nonce = data['nonce']
   block.hash = data['hash']
   if 'fruits' in data:
       block.fruits = [deserialize_fruit(fruit_json) for fruit_json in data['fruits']]
   return block

def serialize_fruit(fruit):
   return json.dumps({
       'timestamp': serialize_datetime(fruit.timestamp),
       'data': fruit.data,
       'referenced_transactions': fruit.referenced_transactions,
       'signature': fruit.signature.hex()
   })

def deserialize_fruit(json_str):
   data = json.loads(json_str)
   fruit = Fruit(data['data'], data['referenced_transactions'], None)  # Adjust as necessary
   fruit.timestamp = deserialize_datetime(data['timestamp'])
   fruit.signature = bytes.fromhex(data['signature'])
   return fruit