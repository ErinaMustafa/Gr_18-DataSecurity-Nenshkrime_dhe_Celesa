import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import binascii
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


CERT_FOLDER = Path("/home/erisasollova/PycharmProjects/UshtrimeDataSecurity/projekti/certifikata")
SERVER_CERT = CERT_FOLDER / "server.crt"
SERVER_KEY = CERT_FOLDER / "server.key"
CLIENT_CERT = CERT_FOLDER / "client.crt"

def print_cert_info(cert_path, title):
    """Shfaq informacione rreth certifikates"""
    print(f"\n {title} Information:")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        print(f"Subject: {cert.subject.rfc4514_string()}")
        print(f"Issuer: {cert.issuer.rfc4514_string()}")

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
            print(f"Valid From: {cert.not_valid_before}")
            print(f"Valid Until: {cert.not_valid_after}")

        print(f"Serial Number: {cert.serial_number}")
        print(f"Public Key: {cert.public_key().public_numbers()}")

def load_certificates():
    """Ngarko certifikatat dhe shfaq informacione"""
    print("\n Serveri po ngarkon certifikatat...")
    print_cert_info(SERVER_CERT, "Server Certificate")
    print_cert_info(CLIENT_CERT, "Client Certificate")

    with open(SERVER_KEY, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def verify_signature(message, signature):
    """Verifiko nenshkrimin dhe shfaq detaje"""
    with open(CLIENT_CERT, "rb") as f:
        client_cert = f.read()

    cert = x509.load_pem_x509_certificate(client_cert, default_backend())
    public_key = cert.public_key()

    print("\n Procesi i Verifikimit të Nenshkrimit:")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    message_hash = digest.finalize()
    print(f"Mesazhi (hash): {binascii.hexlify(message_hash)}")
    print(f"Nenshkrimi i marrur: {binascii.hexlify(signature)}")

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(" Nenshkrimi u verifikua me sukses!")
        return True
    except Exception as e:
        print(f" Verifikimi deshtoi: {e}")
        return False
