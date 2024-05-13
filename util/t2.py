from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_with_public_key(plaintext, public_key_file):
    print('encryptin data')
    # Load the private key from file
    with open(public_key_file, "rb") as f:
        public_key = RSA.importKey(f.read())

    # Create an RSA cipher object with the private key
    cipher = PKCS1_OAEP.new(public_key)

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext.encode())
    print('encryption complete')
    return ciphertext.hex()

def decrypt_with_private_key(ctext, private_key_file):
    print('dencryptin data')
    # Load the private key from file
    with open(private_key_file, "rb") as f:
        private_key = RSA.importKey(f.read())

    # Create an RSA cipher object with the private key
    cipher = PKCS1_OAEP.new(private_key)

    # Encrypt the plaintext
    plaintext = cipher.decrypt(ctext)
    print('dencryption complete')
    return plaintext.decode()
# Example usage
plaintext = "Hello, world!"
private_key_file = "private_key.pem"

encrypted_data = encrypt_with_public_key(plaintext, 'fra_pubkey.pem')

dencrypted_data = decrypt_with_private_key(bytes.fromhex(encrypted_data), 'fra_privkey.pem')
print("Encrypted data:", encrypted_data)
print("Dencrypted data:", dencrypted_data)