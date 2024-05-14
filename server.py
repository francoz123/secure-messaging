import json
import socket
import ssl
from database import *
from util.prorocol import *

# Load messages 
messages = load_messages('data/messages.json')
# Load public keys and users
public_keys = load_public_keys('data/keys.json')
users_dict = load_users('data/users.json')

def main():
  """Creates an SSL socket and listens for connection requests and responds to user requests."""
  if len(sys.argv) != 2:
    print_and_exit("Usage: {} <port>".format(sys.argv[0]))
  PORT = validate_port(sys.argv[1])
  sock= socket_server(PORT) # Create TCP socket
  
  while True:
    server_socket = ssl_socket(sock) # Create SSL socket
    result, user = authenticate(server_socket)
    # Loop until vailid authentication
    while result < 0:
      server_socket.sendall(str(result).encode())
      result, user = authenticate(server_socket)
    username = user['username']
    recipient = ''
    try:
      # Send login status to client
      server_socket.sendall(str(result).encode())
      # Receive user's public key
      data = server_socket.recv(1024)
      # Deserialize JSON string to Python dictionary
      json_data = json.loads(data.decode())
      # Store public key
      public_keys[username] = json_data['pkey']
      save_public_key(username, json_data['pkey'], 'data/keys.json')

      # Check and send mumber of messages
      if not username in messages:
        messages[username] = []
      num_msg = len(messages[username])
      server_socket.sendall(str(num_msg).encode())
      connected = True

      while connected:
        # Receive data from the client
        data = server_socket.recv(1024)
        # Deserialize JSON string to Python dictionary
        json_data = json.loads(data.decode())
        command = json_data['command']

        # READ command
        if command == 'READ':
          if len(messages[username]) > 0:
            current_message = messages[username].pop(0) # Get oldest message
            responese = json.dumps(current_message) # Encode to json
            server_socket.sendall(responese.encode())
            # Store read receipt
            if current_message['type'] == 'unread':
              current_message['type'] = 'read'
              messages[username].append(current_message)
          else:
            responese = 'READ ERROR'
            server_socket.sendall(responese.encode())

        # COMPOSE command
        if command == 'COMPOSE':
          recipient = json_data['recipient']
          # If key request
          if not 'message' in json_data:
            if not recipient in public_keys:
              server_socket.sendall('None'.encode())
            # Send recipients public key
            elif recipient in public_keys:
              server_socket.sendall(public_keys[recipient].encode())
              data = server_socket.recv(2048)
              # Deserialize JSON string to Python dictionary
              json_data = json.loads(data.decode())
              # Construct and store message
              message = {'sender': username, 'message': json_data['message'], 'recipient': recipient, 'hash': \
                        json_data['hash'], 'type': 'unread'}
              if recipient in messages:
                messages[recipient].append(message)
              else:
                messages[recipient] = []
                messages[recipient].append(message)
              responese = 'MESSAGE SENT'
              server_socket.sendall(responese.encode())
            else:
              responese = 'MESSAGE SENT'
              server_socket.sendall(responese.encode())

        # EXIT command
        if command == 'EXIT':
          save_messages(messages, 'data/messages.json')
          connected =False
    except socket.error as se:
      save_messages(messages, 'data/messages.json')
      print(f"Server error: {se}")
      sys.exit(1)
    except Exception as e:
      save_messages(messages, 'data/messages.json')
      print(f"Server error: {e}")
      sys.exit(1)

if __name__ == "__main__":
  main()
