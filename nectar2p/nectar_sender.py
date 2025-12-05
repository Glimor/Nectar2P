import json
import os
import hashlib
import sys
from typing import Tuple

from nectar2p.encryption.rsa_handler import RSAHandler
from nectar2p.encryption.aes_handler import AESHandler
from nectar2p.networking.connection import Connection
from nectar2p.networking.nat_traversal import NATTraversal

class NectarSender:
    def __init__(self, receiver_host: str, receiver_port: int, enable_encryption: bool = True,
                 expected_receiver_public_key: bytes | None = None,
                 stun_server: Tuple[str, int] | None = None):
        self.connection = Connection(receiver_host, receiver_port)
        self.enable_encryption = enable_encryption
        self.expected_receiver_public_key = expected_receiver_public_key
        if self.enable_encryption:
            self.rsa_handler = RSAHandler()
            self.aes_handler = AESHandler()

        self.nat_traversal = NATTraversal(stun_server)
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

            self.connection.send_data(self.rsa_handler.get_public_key())

            aes_key = self.aes_handler.get_key()
            encrypted_aes_key = self.rsa_handler.encrypt_aes_key(aes_key, receiver_public_key)

            self.connection.send_data(encrypted_aes_key)

    def send_file(self, file_path: str):
        try:
            file_size = os.path.getsize(file_path)
        except FileNotFoundError:
            print(f"File '{file_path}' not found.")
            return
        
        if file_size < 0 or file_size > 10 * 1024 * 1024 * 1024:
            print("File size exceeds limit (10GB).")
            return

        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        meta = json.dumps({"size": file_size, "sha256": file_hash}).encode()
        if self.enable_encryption:
            meta = self.aes_handler.encrypt(meta)
        self.connection.send_data(meta)

        ack = self.connection.receive_data()
        if ack is None:
            print("No acknowledgement from receiver.")
            return
        if self.enable_encryption:
            ack = self.aes_handler.decrypt(ack)
        try:
            ack_json = json.loads(ack.decode())
            start_offset = int(ack_json.get("resume_from", 0))
            if start_offset < 0 or start_offset > file_size:
                print("Invalid resume offset.")
                return
        except Exception:
            print("Invalid acknowledgement from receiver.")
            return

        bytes_sent = start_offset
        with open(file_path, "rb") as file:
            file.seek(start_offset)
            while True:
                chunk = file.read(64 * 1024)
                if not chunk:
                    break
                if self.enable_encryption:
                    try:
                        chunk = self.aes_handler.encrypt(chunk)
                    except Exception:
                        print("Encryption failed.")
                        return
                self.connection.send_data(chunk)
                bytes_sent += len(chunk)
                self._print_progress(bytes_sent, file_size)
            self.connection.send_data(b"")
            self._print_progress(file_size, file_size)

    def close_connection(self):
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
