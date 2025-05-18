import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import binascii
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
CERT_FOLDER = Path("/home/erisasollova/PycharmProjects/UshtrimeDataSecurity/projekti/certifikata")
CLIENT_CERT = CERT_FOLDER / "client.crt"
CLIENT_KEY = CERT_FOLDER / "client.key"
SERVER_CERT = CERT_FOLDER / "server.crt"
def print_cert_info(cert_path, title):
    """Shfaq informacione rreth certifikates"""
    print(f"\n {title} Information:")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        print(f"Subject: {cert.subject.rfc4514_string()}")
        print(f"Issuer: {cert.issuer.rfc4514_string()}")
        print(f"Valid From: {cert.not_valid_before_utc}")
        print(f"Valid Until: {cert.not_valid_after_utc}")
        print(f"Serial Number: {cert.serial_number}")
        print(f"Public Key: {cert.public_key().public_numbers()}")

        def load_certificates():
            """Ngarko certifikatat dhe shfaq informacione"""
            print("\n Klienti po ngarkon certifikatat...")
            print_cert_info(CLIENT_CERT, "Client Certificate")
            print_cert_info(SERVER_CERT, "Server Certificate")

            with open(CLIENT_KEY, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )

            with open(SERVER_CERT, "rb") as f:
                server_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                public_key = server_cert.public_key()

            return private_key, public_key

        def sign_message(private_key, message):
            """Krijo nenshkrimin dhe shfaq detaje"""
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            digest = hashes.Hash(hashes.SHA256())
            digest.update(message)
            hash_bytes = digest.finalize()
            print(f"Mesazhi (hash): {binascii.hexlify(hash_bytes)}")
            print(f"\n🔏 Nenshkrimi i krijuar: {binascii.hexlify(signature)}")
            return signature
def hybrid_encrypt(public_key, message):
    """Enkripto mesazhin duke perdorur hybrid encryption (AES + RSA)"""
    try:
        # 1. Gjenero celesin simetrik AES (256-bit)
        aes_key = os.urandom(32)

        # 2. Gjenero IV per AES CFB
        iv = os.urandom(16)

        # 3. Enkripto mesazhin me AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()

        # 4. Enkripto celesin AES me RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 5. Krijo payload: encrypted_key || iv || ciphertext
        final_payload = encrypted_key + b'||' + iv + b'||' + ciphertext
        return final_payload

    except Exception as e:
        print(f"❌ Gabim gjate enkriptimit hibrid: {e}")
        raise