import hashlib
import json
import socket
import ssl
import sys
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
from database import *
from util.uitl import print_and_exit

def ssl_client(server_address, port):
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='./security/server.crt')
  #context.load_default_certs()  # Load default CA certificates (optional)
  #context.check_hostname = False  # Disable hostname verification
  #context.verify_mode = ssl.CERT_NONE  # Disable certificate verification

  # Create a TCP/IP socket
  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # Connect the socket to the server address and port
  client_socket.connect((server_address, port))
  # Wrap the socket with SSL
  ssl_socket = context.wrap_socket(client_socket, server_hostname=server_address)
  return ssl_socket

def socket_server(port):
  # Create a TCP/IP socket
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  # Bind the socket to the address and port
  server_address = ('localhost', port)
  server_socket.bind(server_address)
  print("SSL server is listening...")
  return server_socket

def ssl_socket(server_socket):
  # Listen for incoming connections
  server_socket.listen(5)

  # Accept an incoming connection
  client_socket, client_address = server_socket.accept()
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain(certfile='./security/server.crt', keyfile='./security/private.key')
  # Wrap the socket with SSL
  ssl_socket = context.wrap_socket(client_socket, server_side=True)
  return ssl_socket

def validate_port(port):
  try:
    port = int(port)
    return port
  except ValueError:
    print_and_exit("Usage: {} <port>".format(sys.argv[0]))

def hash_password(password):
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
  users = read_all_credentials('data/users.json')
  try:
    # Receive data from the client
    data = server_socket.recv(1024)
    # Decode received data from bytes to string
    json_string = data.decode()
    
    # Deserialize JSON string to Python dictionary
    user_json = json.loads(json_string)
    found = False

    for user in users:
      if user['username'] == user_json['username'] and user['password'] == hash_password(user_json['password']):
        found = True

    print(hash_password(user_json['password']))

    if user_json['auth_type'] == 'login' and not found:
      return -1, user_json
    elif user_json['auth_type'] == 'register' and found:
      return -2, user_json
    elif user_json['auth_type'] == 'login' and found:
      print(f"User: {user_json['username']} is logged in")
      return 1, user_json
    elif user_json['auth_type'] == 'register' and not found:
      write_credentials(user_json['username'], hash_password(user_json['password']), './data/users.json')
      print(f"User: {user_json['username']} is logged in")
      return 2, user_json
    else:
      return 2, user_json
    print(f"User: {user_json['username']} is logged in")
  except socket.error as se:
     print(f"Server error: {se}")
  except Exception as e:
     print(f"Server error: {e}")


def split_response(response):
  if response[-1] == "\n":
        response = response[:-1]

  msg_parts = response.split(" ", 1)
  command = msg_parts[0]
  remainder = msg_parts[1] if len(msg_parts) > 1 else None
  return command, remainder

def generate_key_files(public_key_file, private_key_file):
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
    print("Public key file created:", public_key_file)

def generate_key_pair(public_key_file, private_key_file):
    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 2048)

    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pk)
    public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, pk)

    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key)
        
    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(private_key)

        

def send_public_key(public_key_file, socket):
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

    socket.sendall(json.dumps({'pkey':public_key_base64}).encode())