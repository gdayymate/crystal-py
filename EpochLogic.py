from CCorev3 import Blockchain

blockchain = Blockchain()

# Enlist a producer for the current epoch
blockchain.enlist_producer("public_key_of_producer")

# Start a new epoch
blockchain.start_new_epoch()
