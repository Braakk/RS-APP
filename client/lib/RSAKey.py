from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class RSAKey:
    def __init__(self, key_size=4096, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        self.key_size = key_size
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.save_key()

    def get_private_key(self):
        """
        Retourne la clé privée en format PEM.
        """
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem.decode('utf-8')

    def get_public_key(self):
        """
        Retourne la clé publique en format PEM.
        """
        public_key = self.private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def save_key(self):
        with open(self.private_key_path, "wb") as private_file:
            private_file.write(self.get_private_key().encode('utf-8'))

    def load_key(self):
        try:
            with open(self.private_key_path, "rb") as private_file:
                private_pem = private_file.read()
                self.private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=None,
                    backend=default_backend()
                )
            return True
        except FileNotFoundError:
            return False
        
    def sign(self, data):
        """
        Signe des données avec la clé privée utilisant SHA-256 comme algorithme de hachage.

        :param data: Les données à signer (type bytes).
        :return: La signature en format binaire.
        """
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature