import socket
import ssl
import sys
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

def validate_port(port):
  try:
    port = int(sys.argv[2])
    return port
  except ValueError:
    print_and_exit("Usage: {} <port>".format(sys.argv[0]))