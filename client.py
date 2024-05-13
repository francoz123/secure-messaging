import json
import socket
import ssl
import sys
from os.path import exists as file_exists
import traceback

from util.uitl import *
from util.prorocol import *

messages = {}
pkeys = {}

def main():
  if len(sys.argv) != 3:
    print_and_exit("Usage: {} <server name> <port>".format(sys.argv[0]))
  PORT = validate_port(sys.argv[2])
  server_address = sys.argv[1]

  username, password, auth_type = get_user_info()
  data = json.dumps({'username': username, 'password':password, 'auth_type':auth_type})
  client_socket = ssl_client(server_address, PORT)

  try:
    # Send data to the server
    client_socket.sendall(data.encode())
    res = int(client_socket.recv(1024).decode())
    print(res)
    while res < 0:
      message = 'Login failed' if res == -1 else 'Username already exists'
      print(message)
      username, password, auth_type = get_user_info()
      data = json.dumps({'username': username, 'password':password, 'auth_type':auth_type})
      client_socket.sendall(data.encode())
      res = int(client_socket.recv(1024).decode())
    print('Login successful')

    pubkey_file = username+"_pubkey.pem";
    privkey_file = username+"_privkey.pem"
    if not file_exists(username+"_privkey.pem") or not file_exists(username+"_pubkey.pem"):
      generate_key_pair(username+"_pubkey.pem", username+"_privkey.pem")
      
    with open(username+"_pubkey.pem", 'rb') as key_file:
      public_key_content = key_file.read()
      send_public_key(username+"_pubkey.pem", client_socket)

    num_msg = int(client_socket.recv(1024).decode())
    print(f"You have {num_msg} unread message(s)")

    connected = True
    while connected:
      # Get user input
      command = input("Enter command: ")
      command = command.upper()
      data = {}

      if command == "READ":
        data['command'] =  command
        client_socket.sendall(json.dumps(data).encode())
        response = client_socket.recv(2048).decode()
        if response == "READ ERROR":
          print(">>> You have no messages\n")
        else:
          response_json = json.loads(response)
          decrypted_message = decrypt_with_private_key(bytes.fromhex(response_json['message']), privkey_file)
          if not hash_password(decrypted_message) == response_json['hash']:
            print('>>> Message might have been tampered with!')
          if response_json['type'] == 'read':
            print(f">>> {response_json['recipient']} read your message: {decrypted_message}\n")
          else:
            print(f">>> {response_json['sender']}\n>>> {decrypted_message}\n")
      elif command == "COMPOSE":
        recipient = get_username2("Enter recipient's name: ")
        message = ascii_input("Enter message to send: ")
        if not recipient in pkeys:
          data = json.dumps({'command': command, 'recipient':recipient})
          client_socket.sendall(data.encode())
          response = client_socket.recv(1024).decode()
          if response == 'None':
            print(f'>>> User {recipient} does not exist. Message was not sent.')
          else:
            pkeys[recipient] = response
            #message_signature = sign_message(message, privkey_file)
            message_hash = hash_password(message)
            encrypted_message = encrypt_with_public_key(message, pubkey_file)
            data = json.dumps({'command': command, 'recipient':recipient, 'message':encrypted_message, 'hash': message_hash})
            client_socket.sendall(data.encode())
            #response = client_socket.recv(1024).decode()
            response = client_socket.recv(2048).decode()
            if response == "MESSAGE SENT":
              print(">>> Message sent successfully\n")
            elif response == "MESSAGE FAILED":
              print(">>> Message failed to send\n")
            else:
              raise ValueError(">>> Invalid response from server")
        
      elif command == "EXIT":
        data['command'] = 'EXIT'
        client_socket.sendall(json.dumps(data).encode())
        print(">>> Disconnected from server")
        connected = False
      else:
        print(">>> Invalid command")

  except Exception as e:
     print(f"Client error: {e}")
     sys.exit(1)
  

if __name__ == "__main__":
  main()
