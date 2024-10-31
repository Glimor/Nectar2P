from nectar2p.encryption.rsa_handler import RSAHandler
from nectar2p.encryption.aes_handler import AESHandler
from nectar2p.networking.connection import Connection
from nectar2p.networking.nat_traversal import NATTraversal

class NectarReceiver:
    def __init__(self, host: str, port: int, enable_encryption: bool = True):
        self.connection = Connection(host, port, listen=True)
        self.enable_encryption = enable_encryption
        if self.enable_encryption:
            self.rsa_handler = RSAHandler()
            self.aes_handler = None

        self.nat_traversal = NATTraversal()
        self.public_ip, self.public_port = self.nat_traversal.get_public_address()
        self.client_connection = None

    def wait_for_sender(self):
        self.client_connection = self.connection.accept_connection()
        if self.client_connection:
            print(f"Connection accepted from {self.client_connection.socket.getpeername()}")
            
            if self.enable_encryption:
                public_key = self.rsa_handler.get_public_key()
                self.client_connection.send_data(public_key)

                encrypted_aes_key = self.client_connection.receive_data()
                if encrypted_aes_key is None:
                    print("Failed to receive encrypted AES key.")
                    return

                aes_key = self.rsa_handler.decrypt_aes_key(encrypted_aes_key)
                if aes_key:
                    self.aes_handler = AESHandler(aes_key)
                else:
                    print("Failed to decrypt AES key.")

    def receive_file(self, save_path: str):
        if not self.client_connection:
            print("No active connection.")
            return

        data = self.client_connection.receive_data()
        if data is None:
            print("Failed to receive file data.")
            return

        if self.enable_encryption and self.aes_handler:
            try:
                decrypted_data = self.aes_handler.decrypt(data)
            except Exception as e:
                print(f"Decryption error: {e}")
                return
        else:
            decrypted_data = data

        try:
            with open(save_path, "wb") as file:
                file.write(decrypted_data)
        except Exception as e:
            print(f"Error saving file: {e}")

    def close_connection(self):
        if self.client_connection:
            self.client_connection.close()
        self.connection.close()
