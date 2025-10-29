import os
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

class SecurityService:
    """
    Handles encryption and decryption of sensitive data.
    """
    def __init__(self):
        key = current_app.config.get('ENCRYPTION_KEY')
        if not key:
            raise ValueError("ENCRYPTION_KEY is not set in the configuration.")
        self.fernet = Fernet(key.encode())

    def encrypt_data(self, data: str) -> str:
        """
        Encrypts a string.
        :param data: The string to encrypt.
        :return: A URL-safe, base64-encoded encrypted string.
        """
        if not data:
            return ""
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data: str) -> str:
        """
        Decrypts an encrypted string.
        :param encrypted_data: The encrypted string to decrypt.
        :return: The original decrypted string.
        """
        if not encrypted_data:
            return ""
        try:
            return self.fernet.decrypt(encrypted_data.encode()).decode()
        except InvalidToken:
            # Handle cases where the token is invalid or corrupted
            current_app.logger.error("Failed to decrypt data: Invalid or corrupted token.")
            return "" # Or raise an exception