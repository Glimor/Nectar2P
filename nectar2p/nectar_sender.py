from nectar2p.encryption.rsa_handler import RSAHandler
from nectar2p.encryption.aes_handler import AESHandler
from nectar2p.networking.connection import Connection
from nectar2p.networking.nat_traversal import NATTraversal

class NectarSender:
    def __init__(self, receiver_host: str, receiver_port: int, enable_encryption: bool = True,
                 expected_receiver_public_key: bytes | None = None):
        self.connection = Connection(receiver_host, receiver_port)
        self.enable_encryption = enable_encryption
        self.expected_receiver_public_key = expected_receiver_public_key
        if self.enable_encryption:
            self.rsa_handler = RSAHandler()
            self.aes_handler = AESHandler()
        
        self.nat_traversal = NATTraversal()
        self.public_ip, self.public_port = self.nat_traversal.get_public_address()

    def initiate_secure_connection(self):
        self.connection.connect()

        if self.enable_encryption:
            receiver_public_key = self.connection.receive_data()
            if receiver_public_key is None:
                print("Failed to receive public key from receiver.")
                return
            if self.expected_receiver_public_key and receiver_public_key != self.expected_receiver_public_key:
                print("Receiver public key mismatch. Aborting connection.")
                self.close_connection()
                return

            # send our public key for receiver verification
            self.connection.send_data(self.rsa_handler.get_public_key())

            aes_key = self.aes_handler.get_key()
            encrypted_aes_key = self.rsa_handler.encrypt_aes_key(aes_key, receiver_public_key)

            self.connection.send_data(encrypted_aes_key)

    def send_file(self, file_path: str):
        try:
            with open(file_path, "rb") as file:
                while True:
                    chunk = file.read(64 * 1024)
                    if not chunk:
                        break
                    if self.enable_encryption:
                        try:
                            chunk = self.aes_handler.encrypt(chunk)
                        except Exception as e:
                            print(f"Encryption failed: {e}")
                            return
                    self.connection.send_data(chunk)
            # send zero-length to mark EOF
            self.connection.send_data(b"")
        except FileNotFoundError:
            print(f"File '{file_path}' not found.")

    def close_connection(self):
        self.connection.close()
