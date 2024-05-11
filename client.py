import socket
import ssl
import sys

from util.uitl import *
from util.prorocol import *
#from database import create_database, save_database, find_user, add_user, read_next_message, save_message

BUFFER_SIZE = 1024

def main():
  if len(sys.argv) != 3:
    print_and_exit("Usage: {} <port>".format(sys.argv[0]))
  print(sys.argv[1])
  PORT = validate_port(sys.argv[2])
  server_address = sys.argv[1]

  # Create a custom trust manager that accepts all certificates
  """   trust_manager = ssl.X509ExtendedTrustManager()
  trust_manager.get_accepted_issuers = lambda: []
  trust_manager.check_client_trusted = lambda chain, auth_type: None
  trust_manager.check_server_trusted = lambda chain, auth_type: None """

  username, password, auth_type = get_user_info()
  client_socket = ssl_client(server_address, PORT)

  try:
      # Send data to the server
      message = f"{username} {password} {auth_type}"
      client_socket.sendall(message.encode())
      print("Sent:", message)

  finally:
      # Close the connection
      client_socket.close()

if __name__ == "__main__":
  main()
""" 

  while True:
      buffer = ssl_socket.recv(BUFFER_SIZE)
      buffer = buffer.decode().strip()
      command, *rest = buffer.split()

      if command == 'EXIT':
          break

      if command == 'READ' and not rest:
          n, message = read_next_message(username)
          if n == 1:
              ssl_socket.send(message.encode())
              remove_node(username)
              sender, msg = message.split(maxsplit=1)
              notification = "[ {} read your message: {} ]".format(username, msg)
              save_message("NOTIFICATION", sender, notification)
          else:
              ssl_socket.send("READ ERROR".encode())

      elif command == 'COMPOSE':
          recipient = rest[0]
          message = ' '.join(rest[1:])
          if save_message(username, recipient, message):
              ssl_socket.send("MESSAGE SENT".encode())
          else:
              ssl_socket.send("MESSAGE FAILED".encode())

      else:
          ssl_socket.send("ERROR".encode())
          break

  save_database(username)
  ssl_socket.shutdown(socket.SHUT_RDWR)
  ssl_socket.close()
  server_fd.close() """


