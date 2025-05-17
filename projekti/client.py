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