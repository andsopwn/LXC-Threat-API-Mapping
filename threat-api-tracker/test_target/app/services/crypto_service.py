import os
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from itsdangerous import URLSafeSerializer
from app.utils.logger import logger

class CryptoService:
    def __init__(self, secret_key: str):
        self.serializer = URLSafeSerializer(secret_key)

    def encrypt(self, data: bytes) -> io.BytesIO:
        logger.info("CryptoService: encrypting data")
        key, iv = os.urandom(16), os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        ct = cipher.encryptor().update(data) + cipher.encryptor().finalize()
        return io.BytesIO(ct)

    def sign(self, message: str) -> str:
        logger.info("CryptoService: signing message")
        return self.serializer.dumps(message)

    def verify(self, token: str, max_age: int = 60):
        logger.info("CryptoService: verifying token")
        return self.serializer.loads(token, max_age=max_age)
