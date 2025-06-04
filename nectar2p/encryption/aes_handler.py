from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AESHandler:
    def __init__(self, key: bytes = None):
        self.key = key if key else os.urandom(32)

        if len(self.key) not in {16, 24, 32}:
            raise ValueError("AES key must be either 16, 24, or 32 bytes in length.")

    def get_key(self) -> bytes:
        return self.key

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        aesgcm = AESGCM(self.key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
