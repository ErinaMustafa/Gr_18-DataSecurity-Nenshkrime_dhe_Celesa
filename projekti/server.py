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

    with open(CLIENT_CERT, "rb") as f:
        client_cert = f.read()

    cert = x509.load_pem_x509_certificate(client_cert, default_backend())
    public_key = cert.public_key()

    print("\n Procesi i Verifikimit të Nenshkrimit:")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    message_hash = digest.finalize()
    print(f"Mesazhi (hash): {binascii.hexlify(message_hash)}")
    print(f" Nenshkrimi i marre: {binascii.hexlify(signature)}")

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


def hybrid_decrypt(private_key, encrypted_payload):

    try:

        parts = encrypted_payload.split(b'||')
        if len(parts) != 3:
            raise ValueError("Formati i payload-it eshte i pavlefshem")

        encrypted_key = parts[0]
        iv = parts[1]
        ciphertext = parts[2]


        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_data
    except Exception as e:
        print(f" Gabim gjate dekriptimit hibrid: {e}")
        raise


def start_server():
    host = 'localhost'
    port = 5000

    private_key = load_certificates()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CLIENT_CERT)
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen(1)
        print(f"\n Serveri po pret lidhje ne {host}:{port}...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                print(f"\n Lidhja u krijua me: {addr}")

                encrypted_data = conn.recv(4096)
                print(f"\n Mesazhi i kriptuar i marre ({len(encrypted_data)} bytes)")

                try:

                    decrypted_data = hybrid_decrypt(private_key, encrypted_data)
                    print(f"\n Mesazhi i dekriptuar: {binascii.hexlify(decrypted_data)}")

                    # Ndaj mesazhin dhe nënshkrimin
                    message, signature = decrypted_data.split(b'||SIG||')
                    print(f"\n Mesazhi i paster: {message.decode('utf-8')}")

                    # Verifiko nënshkrimin
                    if verify_signature(message, signature):
                        response = " Serveri pranoi mesazhin dhe verifikoi nenshkrimin!"
                        print(f"\n{response}")
                        conn.sendall(response.encode('utf-8'))
                    else:
                        response = " Serveri nuk verifikoi nenshkrimin!"
                        print(f"\n{response}")
                        conn.sendall(response.encode('utf-8'))

                except Exception as e:
                    error_msg = f" Gabim në perpunim: {str(e)}"
                    print(f"\n{error_msg}")
                    conn.sendall(error_msg.encode('utf-8'))

