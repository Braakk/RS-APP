import json
from cryptography.fernet import Fernet

class EncryptedMessage:
    def __init__(self, sender: str, recipient: str, message: str, key: bytes):
        self.sender = sender
        self.recipient = recipient
        self.encrypted_message = self.encrypt_message(message, key)

    @staticmethod
    def encrypt_message(message: str, key: bytes) -> bytes:
        """
        Encrypts the message with the provided key.
        """
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())
        return encrypted_message

    @staticmethod
    def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
        """
        Decrypts the message with the provided key.
        """
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        return decrypted_message
    
    # Serialization of the object
    def serialize(self) -> str:
        """
        Serialize the object to a JSON string.
        """
        return json.dumps(self.__dict__)