# hybrid_crypto.py

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

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
        print(f"Gabim gjate enkriptimit hibrid: {e}")
        raise
