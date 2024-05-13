import hashlib
import json
import socket
import ssl
import sys
from cryptography.hazmat.backends import *
from OpenSSL import crypto
from database import *
from util.uitl import print_and_exit

def ssl_client(server_address, port):
  """
    Creates SSL client socket.

    Args:
        server_address (str): The address of the server.
        port (int): Server port number.

    Returns:
        int: File descriptor.
    """
  # Create SSL context and set verification
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='./security/server.crt')
  # Create a TCP/IP socket
  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # Connect the socket to the server address and port
  client_socket.connect((server_address, port))
  # Wrap the socket with SSL
  ssl_socket = context.wrap_socket(client_socket, server_hostname=server_address)
  return ssl_socket

def socket_server(port):
  """
    Creates and binds server socket to a port.

    Args:
        port (int): Server port number.

    Returns:
        int: File descriptor.
    """
  # Create a TCP/IP socket
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  # Bind the socket to the address and port
  server_address = ('localhost', port)
  server_socket.bind(server_address)
  print("SSL server is listening...")
  return server_socket

def ssl_socket(server_socket):
  """
    Listens, accept connections, and returns SSL socket.

    Args:
        server_socket (int): Server socket file descriptor.
    Returns:
        int: File descriptor.
    """
  # Listen for incoming connections
  server_socket.listen(5)
  # Accept an incoming connection
  client_socket, _ = server_socket.accept()
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  # Load certificate
  context.load_cert_chain(certfile='./security/server.crt', keyfile='./security/private.key')
  # Wrap the socket with SSL
  ssl_socket = context.wrap_socket(client_socket, server_side=True)
  return ssl_socket

def validate_port(port):
  """
    Ensures the port number is an integer;

    Args:
        port (int): port number.
    Returns:
        None
  """
  try:
    port = int(port)
    return port
  except ValueError:
    print_and_exit("Usage: {} <port>".format(sys.argv[0]))

def hash_password(password):
  """
    Returns a string's hash value

    Args:
        Input_str (str): A string to hash.
    Returns:
        bytes: byte value of the hash
  """
  # Convert the plain text password to bytes
  password_bytes = password.encode('utf-8')
  # Choose a hash algorithm (e.g., SHA-256)
  hash_algorithm = hashlib.sha256()
  # Update the hash object with the password bytes
  hash_algorithm.update(password_bytes)
  # Get the hexadecimal digest (hashed value)
  hashed_password = hash_algorithm.hexdigest()

  return hashed_password

def authenticate(server_socket):
  """
    Authenticates a user

    Args:
      server_socket (int): Server file descriptor
    Return:
      int, {str, str} (Tupple): Authentication status and user details
  """
  # Load users to memory
  users = read_all_credentials('data/users.json')
  try:
    # Receive data from the client
    data = server_socket.recv(1024)
    # Decode received data from bytes to string
    json_string = data.decode()
    
    # Deserialize JSON string to Python dictionary
    user_json = json.loads(json_string)
    found = False
    # Authenticate user
    for user in users:
      if user['username'] == user_json['username'] and user['password'] == hash_password(user_json['password']):
        found = True

    if user_json['auth_type'] == 'login' and not found:
      return -1, user_json
    elif user_json['auth_type'] == 'register' and found:
      return -2, user_json
    elif user_json['auth_type'] == 'login' and found:
      print(f"User {user_json['username']} is logged in")
      return 1, user_json
    elif user_json['auth_type'] == 'register' and not found:
      write_credentials(user_json['username'], hash_password(user_json['password']), './data/users.json')
      print(f"User {user_json['username']} is logged in")
      return 2, user_json
    return None, None
  except socket.error as se:
     print(f"Server error: {se}")
  except Exception as e:
     print(f"Server error: {e}")


""" def split_response(response):
  if response[-1] == "\n":
        response = response[:-1]

  msg_parts = response.split(" ", 1)
  command = msg_parts[0]
  remainder = msg_parts[1] if len(msg_parts) > 1 else None
  return command, remainder """

""" def generate_key_files(public_key_file, private_key_file):
    # Check if key files already exist
    if Path(public_key_file).exists() and Path(private_key_file).exists():
        print("Key files already exist.")
        return

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize and save private key
    with open(private_key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print("Private key file created:", private_key_file)

    # Serialize and save public key
    public_key = private_key.public_key()
    with open(public_key_file, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("Public key file created:", public_key_file) """

def generate_key_pair(public_key_file, private_key_file):
    """
      Generates asymetric key pair and stores them

      Args:
        public_key_file (str): public key file name
        private_key_file (str): private key file name
    """
    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 2048)

    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pk)
    public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, pk)

    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key)
        
    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(private_key)

        
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def send_public_key(public_key_file, socket):
  """
    Sends user public key to the server

    Args:
      public_key_file (str): public key file name
      socket (int): client file descriptor
  """
  # Load the public key from file
  with open(public_key_file, "rb") as f:
      public_key_bytes = f.read()

  # Convert the public key bytes to PEM format
  public_key = serialization.load_pem_public_key(public_key_bytes)

  # Encode the public key in Base64
  public_key_base64 = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
  ).decode()
  # Send key
  socket.sendall(json.dumps({'pkey':public_key_base64}).encode())

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
    
""" def sign_message(message, private_key_file):
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

    print('signing message complete')
    return signature.hex() """

""" def verify_signature(message, signature, public_key_file):
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
      print('verifying signature done')

      return True
    except Exception as e:
      print('verifying signature failed')
      return False """

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_with_public_key(plaintext, public_key_file):
  """
    Encrypts plaintext
    Args:
      plaintext (str): Text to be encrypted
      public_key_file (srt): public key file name
    Return:
      hex: Hex value of the cypher text
  """
  # Load the private key from file
  with open(public_key_file, "rb") as f:
      public_key = RSA.importKey(f.read())

  # Create an RSA cipher object with the private key
  cipher = PKCS1_OAEP.new(public_key)

  # Encrypt the plaintext
  ciphertext = cipher.encrypt(plaintext.encode())
  return ciphertext.hex()

def encrypt_with_public_key2(plaintext, public_key):
  """
    Encrypts plaintext
    Args:
      plaintext (str): Text to be encrypted
      public_key_file (srt): public key file name
    Return:
      hex: Hex value of the cypher text
  """
  # Load the private key from file
  public_key = RSA.importKey(public_key.encode())

  # Create an RSA cipher object with the private key
  cipher = PKCS1_OAEP.new(public_key)

  # Encrypt the plaintext
  ciphertext = cipher.encrypt(plaintext.encode())
  return ciphertext.hex()

def decrypt_with_private_key(cyphertext, private_key_file):
  """
    Dencrypts cyphertext
    Args:
      cyphertext (byte): Text to be decrypted
      public_key_file (srt): public key file name
    Return:
      str: original text
  """
  # Load the private key from file
  with open(private_key_file, "rb") as f:
      private_key = RSA.importKey(f.read())

  # Create an RSA cipher object with the private key
  cipher = PKCS1_OAEP.new(private_key)

  # Encrypt the plaintext
  plaintext = cipher.decrypt(cyphertext)
  return plaintext.decode()