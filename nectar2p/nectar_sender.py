from nectar2p.encryption.rsa_handler import RSAHandler
from nectar2p.encryption.aes_handler import AESHandler
from nectar2p.networking.connection import Connection
from nectar2p.networking.nat_traversal import NATTraversal

class NectarSender:
    def __init__(self, receiver_host: str, receiver_port: int, enable_encryption: bool = True):
        self.connection = Connection(receiver_host, receiver_port)
        self.enable_encryption = enable_encryption
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

            aes_key = self.aes_handler.get_key()
            encrypted_aes_key = self.rsa_handler.encrypt_aes_key(aes_key, receiver_public_key)

            self.connection.send_data(encrypted_aes_key)

    def send_file(self, file_path: str):
        try:
            with open(file_path, "rb") as file:
                data = file.read()
        except FileNotFoundError:
            print(f"File '{file_path}' not found.")
            return

        if self.enable_encryption:
            try:
                encrypted_data = self.aes_handler.encrypt(data)
            except Exception as e:
                print(f"Encryption failed: {e}")
                return
            self.connection.send_data(encrypted_data)
        else:
            self.connection.send_data(data)

    def close_connection(self):
        self.connection.close()
