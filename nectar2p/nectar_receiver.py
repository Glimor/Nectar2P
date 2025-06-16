import json
import os
import hashlib
import sys
from typing import Tuple

from nectar2p.encryption.rsa_handler import RSAHandler
from nectar2p.encryption.aes_handler import AESHandler
from nectar2p.networking.connection import Connection
from nectar2p.networking.nat_traversal import NATTraversal

class NectarReceiver:
    def __init__(self, host: str, port: int, enable_encryption: bool = True,
                 expected_sender_public_key: bytes | None = None,
                 stun_server: Tuple[str, int] | None = None):
        self.connection = Connection(host, port, listen=True)
        self.enable_encryption = enable_encryption
        self.expected_sender_public_key = expected_sender_public_key
        if self.enable_encryption:
            self.rsa_handler = RSAHandler()
            self.aes_handler = None

        self.nat_traversal = NATTraversal(stun_server)
        self.public_ip, self.public_port = self.nat_traversal.get_public_address()
        self.client_connection = None

    def wait_for_sender(self):
        self.client_connection = self.connection.accept_connection()
        if self.client_connection:
            print(f"Connection accepted from {self.client_connection.socket.getpeername()}")
            
            if self.enable_encryption:
                # send our public key
                public_key = self.rsa_handler.get_public_key()
                self.client_connection.send_data(public_key)

                # receive sender public key for verification
                sender_public_key = self.client_connection.receive_data()
                if sender_public_key is None:
                    print("Failed to receive sender public key.")
                    return
                if self.expected_sender_public_key and sender_public_key != self.expected_sender_public_key:
                    print("Sender public key mismatch. Aborting connection.")
                    self.close_connection()
                    return

                encrypted_aes_key = self.client_connection.receive_data()
                if encrypted_aes_key is None:
                    print("Failed to receive encrypted AES key.")
                    return

                aes_key = self.rsa_handler.decrypt_aes_key(encrypted_aes_key)
                if aes_key:
                    self.aes_handler = AESHandler(aes_key)
                else:
                    print("Failed to decrypt AES key.")

    def receive_file(self, save_path: str, resume: bool = False):
        if not self.client_connection:
            print("No active connection.")
            return

        try:
            meta = self.client_connection.receive_data()
            if meta is None:
                print("Failed to receive file metadata.")
                return
            if self.enable_encryption and self.aes_handler:
                meta = self.aes_handler.decrypt(meta)
            meta_json = json.loads(meta.decode())
            file_size = int(meta_json.get("size", 0))
            expected_hash = meta_json.get("sha256", "")

            received_size = 0
            if resume and os.path.exists(save_path):
                received_size = os.path.getsize(save_path)
            ack = json.dumps({"resume_from": received_size}).encode()
            if self.enable_encryption and self.aes_handler:
                ack = self.aes_handler.encrypt(ack)
            self.client_connection.send_data(ack)

            mode = "ab" if resume and received_size > 0 else "wb"
            bytes_written = received_size
            with open(save_path, mode) as file:
                while True:
                    data = self.client_connection.receive_data()
                    if data is None:
                        print("Failed to receive file data.")
                        return
                    if len(data) == 0:
                        break
                    if self.enable_encryption and self.aes_handler:
                        try:
                            data = self.aes_handler.decrypt(data)
                        except Exception as e:
                            print(f"Decryption error: {e}")
                            return
                    file.write(data)
                    bytes_written += len(data)
                    self._print_progress(bytes_written, file_size)
            self._print_progress(file_size, file_size)

            actual_size = os.path.getsize(save_path)
            if actual_size != file_size:
                print("Warning: transferred file size mismatch.")

            sha256 = hashlib.sha256()
            with open(save_path, "rb") as f:
                for chunk in iter(lambda: f.read(64 * 1024), b""):
                    sha256.update(chunk)
            if sha256.hexdigest() != expected_hash:
                print("Warning: file integrity verification failed.")
        except Exception as e:
            print(f"Error saving file: {e}")

    def close_connection(self):
        if self.client_connection:
            self.client_connection.close()
        self.connection.close()

    @staticmethod
    def _print_progress(current: int, total: int):
        if total == 0:
            return
        percent = int(current * 100 / total)
        bar_length = 50
        filled = int(bar_length * percent / 100)
        bar = "#" * filled + "-" * (bar_length - filled)
        sys.stdout.write(f"\r[{bar}] {percent}%")
        sys.stdout.flush()
        if current >= total:
            sys.stdout.write("\n")
