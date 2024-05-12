import json
import socket
import ssl
from database import *
from util.prorocol import *

messages = {}
pkeys = {}

def main():
  if len(sys.argv) != 2:
    print_and_exit("Usage: {} <port>".format(sys.argv[0]))
  PORT = validate_port(sys.argv[1])
  sock= socket_server(PORT)
  
  while True:
    server_socket = ssl_socket(sock)
    result, user = authenticate(server_socket)

    while result < 0:
      server_socket.sendall(str(result).encode())
      result, user = authenticate(server_socket)
    username = user['username']
    recipient = ''
    try:
      server_socket.sendall(str(result).encode())
      
      data = server_socket.recv(1024)
      # Deserialize JSON string to Python dictionary
      json_data = json.loads(data.decode())
      pkeys[username] = json_data['pkey']

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
        if command == 'READ':
          if len(messages[username]) > 0:
            current_message = messages[username].pop(0)
            responese = json.dumps(current_message)
            server_socket.sendall(responese.encode())
            if current_message['type'] == 'unread':
              current_message['type'] = 'read'
              messages[username].append(current_message)
          else:
            responese = 'READ ERROR'
            server_socket.sendall(responese.encode())
        if command == 'COMPOSE':
          recipient = json_data['recipient']
          if not 'message' in json_data:
            if not recipient in pkeys:
              server_socket.sendall('None'.encode())
            elif recipient in pkeys:
              server_socket.sendall(pkeys[recipient].encode())
              data = server_socket.recv(2048)
              # Deserialize JSON string to Python dictionary
              json_data = json.loads(data.decode())
            
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
        if command == 'EXIT':
          connected =False
    except socket.error as se:
      print(f"Server error: {se}")
      sys.exit(1)
    except Exception as e:
      print(f"Server error: {e}")
      sys.exit(1)

if __name__ == "__main__":
  main()
