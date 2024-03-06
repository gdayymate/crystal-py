class CommitteeManager:
  def __init__(self):
      self.enlisted_producers = {}
      self.current_epoch = 0

  def enlist_producer(self, public_key):
     """Enlists a producer for the current epoch."""
     if not self.is_valid_public_key(public_key):
         raise ValueError("Invalid public key.")

     if self.current_epoch + 1 not in self.enlisted_producers:
        self.enlisted_producers[self.current_epoch + 1] = []

     self.enlisted_producers[self.current_epoch].append(public_key)

  def start_next_epoch(self):
     """Starts a new epoch and resets the list of registered producers."""
     self.current_epoch += 1
     self.enlisted_producers[self.current_epoch] = []

  def get_active_producers(self):
     """Returns the active producers for the current epoch."""
     return self.enlisted_producers.get(self.current_epoch, [])

  @staticmethod
  def is_valid_public_key(public_key):
     try:
         VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
         return True
     except Exception:
         return False
