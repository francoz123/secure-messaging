import hashlib
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from OpenSSL import crypto

def sign_message(message, private_key_file):
    print('signing message')
    # Load the private key from file
    with open(private_key_file, "rb") as f:
        private_key_bytes = f.read()

    # Convert the private key bytes to PEM format
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
    )

    # Hash the message
    digest = hashlib.sha256(message.encode()).digest()

    # Sign the hashed message using the private key
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def verify_signature(message, signature, public_key_file):
    print('verifying signature')
    # Load the public key from file
    with open(public_key_file, "rb") as f:
        public_key_bytes = f.read()

    # Convert the public key bytes to PEM format
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    # Hash the message
    digest = hashlib.sha256(message.encode()).digest()

    # Verify the signature using the public key
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False
def encrypt_message(message, public_key_file):
    print("encrypting message")
    # Load the public key from file
    with open(public_key_file, "rb") as f:
        #public_key_bytes = bytes.fromhex(f.read())
        public_key_bytes = f.read()

    # Convert the public key bytes to PEM format
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    # Encrypt the message using the public key
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext.hex()

def decrypt_message(encrypted_message, private_key_file):
    print("encrypting message")
    # Load the private key from file
    with open(private_key_file, "rb") as f:
        private_key_bytes = f.read()

    # Convert the private key bytes to PEM format
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )

    # Decrypt the encrypted message using the private key
    encrypted_message_bytes = bytes.fromhex(encrypted_message)
    plaintext = private_key.decrypt(
        encrypted_message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=padding.MGF1(hashes.SHA256())),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode()

if __name__ == "__main__":
    msg = 'Hello'
    ec = encrypt_message(msg, 'fra_pubkey.pem')
    print(ec)
    print(decrypt_message(ec, 'fra_privkey.pem'))