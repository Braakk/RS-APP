from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption, Encoding, PrivateFormat, PublicFormat
from cryptography.hazmat.backends import default_backend
import datetime
import os

def generate_ssl_certificates(certPath: str = "certs/server.crt", keyPath: str = "certs/server.key", password=None):
    # Check if the certificates already exist, if not generate them
    if os.path.exists(certPath) and os.path.exists(keyPath):
        print("Loading existing SSL certificates...")
        return
    
    print("Generating default SSL certificates...")

    # Creates the folder if necessary, including parent folders
    os.makedirs(os.path.dirname(certPath), exist_ok=True)
    
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Generate a Certificate Signing Request (CSR)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"IDF"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Mastercamp"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"RS-APP"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        # Le certificat est valide pour 1 an
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Write the private key to a file
    with open(keyPath, "wb") as key_file:
        if password:
            encryption_algorithm = BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = NoEncryption()
        key_file.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm,
        ))

    # Write the certificate to a file
    with open(certPath, "wb") as cert_file:
        cert_file.write(cert.public_bytes(Encoding.PEM))

    print("Default SSL certificates generated.")