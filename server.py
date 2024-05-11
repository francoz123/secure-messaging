import socket
import ssl

def ssl_server():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_address = ('localhost', 12345)
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(5)

    print("SSL server is listening...")

    # Accept an incoming connection
    client_socket, client_address = server_socket.accept()
    #context = ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='./security/server.crt', keyfile='./security/private.key')
    # Wrap the socket with SSL
    ssl_socket = context.wrap_socket(client_socket, server_side=True)

    try:
        # Receive data from the client
        data = ssl_socket.recv(1024)
        print("Received:", data.decode())

    finally:
        # Close the connection
        ssl_socket.close()

if __name__ == "__main__":
    ssl_server()
