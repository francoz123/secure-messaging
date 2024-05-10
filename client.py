import socket
import ssl
import sys
from database import create_database, save_database, find_user, add_user, read_next_message, save_message

BUFFER_SIZE = 1024

def main():
    if len(sys.argv) != 2:
        print("Usage: {} <port>".format(sys.argv[0]))
        sys.exit(1)

    PORT = int(sys.argv[1])

    # Socket variables
    server_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_fd.bind(('localhost', PORT))
    server_fd.listen(3)

    print("Waiting connection...")
    # Accept connections with client_fd
    client_fd, addr = server_fd.accept()
    print("Connection established.")

    # Initialize SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    # Wrap the socket
    ssl_socket = context.wrap_socket(client_fd, server_side=True)

    # Read authentication token
    auth_data = ssl_socket.recv(BUFFER_SIZE)
    auth = auth_data.decode().split()

    username, password = auth[0], auth[1]

    # Sign up user if necessary
    if auth[2] == 'signup':
        if not find_user(username, password, 0):
            add_user(username, password)
        num_msg = -2

        while num_msg == -2 and find_user(username, password, 0):
            ssl_socket.send(str(num_msg).encode())
            auth_data = ssl_socket.recv(BUFFER_SIZE)
            auth = auth_data.decode().split()
            username, password = auth[0], auth[1]

    # Ensure user exists
    while not find_user(username, password, 1):
        ssl_socket.send(str(num_msg).encode())
        auth_data = ssl_socket.recv(BUFFER_SIZE)
        auth = auth_data.decode().split()
        username, password = auth[0], auth[1]

    # Populate linked list of messages and return number of messages for the user
    num_msg = create_database(username)
    # Send result to the client
    ssl_socket.send(str(num_msg).encode())

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
    server_fd.close()

if __name__ == "__main__":
    main()
