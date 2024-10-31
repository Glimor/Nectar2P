from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class AESHandler:
    def __init__(self, key: bytes = None):
        self.key = key if key else os.urandom(32)

        if len(self.key) not in {16, 24, 32}:
            raise ValueError("AES key must be either 16, 24, or 32 bytes in length.")

    def get_key(self) -> bytes:
        return self.key

    def encrypt(self, data: bytes) -> bytes:
        iv = os.urandom(16)
        if len(iv) != 16:
            raise ValueError("Invalid IV size for AES encryption.")
        
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(data) + encryptor.finalize()
        return ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        if len(iv) != 16:
            raise ValueError("Invalid IV size for AES decryption.")
        
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
