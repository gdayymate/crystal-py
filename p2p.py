#P2P
import requests
from flask import Flask, jsonify, request
from CCorev3 import Blockchain, Fruit, Stem, Leaf
from p2p import P2PNode
from net_serialize import serialize_block, deserialize_block, serialize_fruit, deserialize_fruit

app = Flask('crystal')
blockchain = Blockchain()
node = P2PNode(blockchain, ['http://peer1', 'http://peer2'])

@app.route('/get_latest_block', methods=['GET'])
def get_latest_block():
  latest_block = blockchain.get_last_block()
  return jsonify({'block': serialize_block(latest_block)})

@app.route('/add_block', methods=['POST'])
def add_block():
  block_json = request.get_json()
  block = deserialize_block(block_json, block_type='Stem')  # Or 'Leaf' depending on the received data

  if blockchain.is_valid_block(block):
    blockchain.add_block(block)
    node.multicast_fruit(block)
    return jsonify({'message': 'Block added successfully.'}), 201
  else:
    return jsonify({'error': 'Invalid block.'}), 400

@app.route('/new_fruit', methods=['POST'])
def new_fruit():
  fruit_json = request.get_json()
  fruit = deserialize_fruit(fruit_json)
  blockchain.add_fruit(fruit)
  return '', 200

@app.route('/new_block_hash', methods=['POST'])
def new_block_hash():
  data = request.get_json()
  block_hash = data['hash']
  block_type = data['type']
  full_block = node.get_full_block(block_hash, block_type)
  block = deserialize_block(full_block, block_type)

  if blockchain.is_valid_block(block):
    blockchain.add_block(block)
    return '', 200
  else:
    return jsonify({'error': 'Invalid block.'}), 400

@app.route('/request_blocks', methods=['GET'])
def request_blocks():
  latest_block = blockchain.get_last_block().to_dict()
  latest_hash = latest_block['hash']
  latest_type = latest_block['type']
  full_latest_block = node.get_full_block(latest_hash, latest_type)
  # Compare received blocks and update local chain accordingly

if __name__ == '__main__':
  app.run(port=5000)
node.listen_for_messages()