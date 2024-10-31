from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class RSAHandler:
    def __init__(self, key_size: int = 2048):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        self.public_key = self.private_key.public_key()

    def get_private_key(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_public_key(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_aes_key(self, aes_key: bytes, public_key: bytes) -> bytes:
        receiver_public_key = serialization.load_pem_public_key(public_key)
        encrypted_aes_key = receiver_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_aes_key

    def decrypt_aes_key(self, encrypted_aes_key: bytes) -> bytes:
        try:
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return aes_key
        except Exception as e:
            print(f"Decryption failed: {e}")
            print("Invalid Key or File Type")
            return None
