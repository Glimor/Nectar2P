from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

class AESHandler:
    def __init__(self, key: bytes = None):
        self.key = key if key else secrets.token_bytes(32)
        self.used_nonces = set()
        self.max_nonces = 10000

        if len(self.key) not in {16, 24, 32}:
            raise ValueError("AES key must be either 16, 24, or 32 bytes in length.")

    def get_key(self) -> bytes:
        return self.key

    def encrypt(self, data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        if nonce in self.used_nonces:
            raise ValueError("Nonce reuse detected - possible replay attack")
        
        aesgcm = AESGCM(self.key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        if len(self.used_nonces) >= self.max_nonces:
            self.used_nonces.clear()
        self.used_nonces.add(nonce)
        
        return plaintext
