import coincurve
from typing import List

class Transaction:
   ...

   @staticmethod
   def create(private_keys: List[bytes], inputs: List[Tuple[bytes, int]], outputs: List[Tuple[bytes, int]]):
       tx_data = ''.join([f"{inp[0].hex()} {inp[1]} " for inp in inputs]) + \
                ''.join([f"{out[0].hex()} {out[1]} " for out in outputs]).encode('utf-8')

       message = blake3.blake3(tx_data).digest()
       signatures = [Transaction._sign(message, pk) for pk in private_keys]
       merged_sig = Transaction._merge_signatures(signatures)

       return Transaction(inputs, outputs, merged_sig)

   @staticmethod
   def _sign(message: bytes, private_key: bytes) -> str:
       sk = coincurve.PrivateKey(private_key)
       sig = sk.sign_recoverable(message, hasher=None)
       return base64.b64encode(sig).decode('ascii')

   @staticmethod
   def _verify_aggregated_signature(pub_keys: List[bytes], signature: str, message: bytes) -> bool:
       try:
           sig = base64.b64decode(signature)

           # Verify each public key against the signature
           for pub_key in pub_keys:
               vk = coincurve.PublicKey(pub_key)
               if vk.verify_recoverable(sig, message, hasher=None):
                  return True

           return False
       except Exception as e:
           print("Invalid signature:", e)
           return False