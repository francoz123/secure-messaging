import rsa

# Generate a public key and a private key
(public_key, private_key) = rsa.newkeys(2048)

# Message to be signed
message = 'Hello, World!'.encode('utf8')

# Sign the message with the private key
signature = rsa.sign(message, private_key, 'SHA-256')

# Verify the signature
try:
    rsa.verify(message, signature, public_key)
    print("The signature is valid.")
except rsa.VerificationError:
    print("The signature is not valid.")


import rsa

# Generate a public key and a private key
(public_key, private_key) = rsa.newkeys(2048)

# Message to be encrypted
message = 'Hello, World!'.encode('utf8')

# Encrypt the message with the public key
encrypted_message = rsa.encrypt(message, public_key)

print('Encrypted message:', encrypted_message)

# Decrypt the message with the private key
decrypted_message = rsa.decrypt(encrypted_message, private_key)

print('Decrypted message:', decrypted_message.decode('utf8'))

import rsa

# Generate a public key and a private key
(public_key, private_key) = rsa.newkeys(2048)

# Save the keys to files
with open('public_key.pem', 'wb') as f:
    f.write(public_key.save_pkcs1())

with open('private_key.pem', 'wb') as f:
    f.write(private_key.save_pkcs1())

# Load the keys from files
with open('public_key.pem', 'rb') as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open('private_key.pem', 'rb') as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

# Generate a public key and a private key
(public_key, private_key) = rsa.newkeys(2048)

# Save the keys to files
with open('public_key.pem', 'wb') as f:
    f.write(public_key.save_pkcs1())

# Load the public key from file
with open('public_key.pem', 'rb') as f:
    public_key_data = f.read()

