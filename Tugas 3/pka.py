import socket
import threading
from rsa import RSA_Algorithm

KEYS = {}

def generate_key():
    global KEYS
    if not KEYS:
        client1_public_key, client1_private_key = RSA_Algorithm.generate_keypair()
        print(f"Public Key Authority Public Key: {client1_public_key}")
        print(f"Public Key Authority Private Key: {client1_private_key}")

        client2_public_key, client2_private_key = RSA_Algorithm.generate_keypair()
        print(f"Public Key Authority Public Key: {client2_public_key}")
        print(f"Public Key Authority Private Key: {client2_private_key}")

        KEYS = {
            "client1_public_key": client1_public_key,
            "client1_private_key": client1_private_key,
            "client2_public_key": client2_public_key,
            "client2_private_key": client2_private_key,
        }

def handle_client(client_socket):
    try:
        role = client_socket.recv(1024).decode('utf-8')
        if role in KEYS:
            key = KEYS[role]
            client_socket.sendall(str(key).encode('utf-8'))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def start_server():
    try:
        generate_key()
        host = "0.0.0.0"
        port = 65432

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"PKA Server started on {host}:{port}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()
            
    except KeyboardInterrupt:
        print("\nServer interrupted by user. Shutting down...")

    finally:
        server_socket.close()
        print("Server socket closed. Goodbye!")

if __name__ == "__main__":
    start_server()
