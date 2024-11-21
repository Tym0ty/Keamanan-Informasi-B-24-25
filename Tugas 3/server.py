import socket
import threading
from des import des_decrypt, des_encrypt
from rsa import RSA_Algorithm

# Generate RSA keypair for the Public Key Authority (PKA)
public_key, private_key = RSA_Algorithm.generate_keypair()
print(f"Public Key Authority Public Key: {public_key}")
print(f"Public Key Authority Private Key: {private_key}")

# Server setup
host = '127.0.0.1'
port = 65432
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(5)  # Allow up to 5 clients

clients = []
client_keys = {}  # Map client sockets to DES keys
client_ids = {}  # Map client sockets to IDs


def broadcast_message(message, sender_socket):
    """
    Broadcast a message to all clients except the sender, with sender identity.
    """
    sender_id = client_ids[sender_socket]
    formatted_message = f"Pesan dari client {sender_id}: {message}"
    for client in clients:
        if client != sender_socket:
            des_key = client_keys[client]
            encrypted_message = des_encrypt(formatted_message, des_key)
            encrypted_message_str = ','.join(map(str, encrypted_message))
            try:
                client.send(encrypted_message_str.encode())
            except Exception as e:
                print(f"Error sending message to {client.getpeername()}: {e}")


def handle_client(client_socket, client_address):
    """
    Handle communication with a client.
    """
    try:
        # Assign an ID to the client
        client_id = len(clients)
        client_ids[client_socket] = client_id

        # Send the public key of the PKA to the client
        client_socket.send(f"{public_key[0]},{public_key[1]}".encode())
        print(f"Public key sent to {client_address} (Client {client_id}).")

        # Receive encrypted DES key from the client
        encrypted_des_key = client_socket.recv(4096).decode()
        encrypted_des_key = list(map(int, encrypted_des_key.split(',')))
        print(f"Encrypted DES key from {client_address} (Client {client_id}): {encrypted_des_key}")
        des_key = RSA_Algorithm.decrypt(encrypted_des_key, private_key)
        client_keys[client_socket] = des_key
        print(f"Decrypted DES key from {client_address}: {des_key}")

        # Main loop to handle incoming messages
        while True:
            encrypted_message = client_socket.recv(4096).decode()
            if encrypted_message.lower() == 'exit':
                print(f"Client {client_address} disconnected.")
                break

            encrypted_message_bits = list(map(int, encrypted_message.split(',')))
            print(f"Encrypted message from Client {client_ids[client_socket]}: {encrypted_message_bits}")
            decrypted_message = des_decrypt(encrypted_message_bits, des_key)
            print(f"Decrypted message from Client {client_ids[client_socket]}: {decrypted_message}")

            # Broadcast the decrypted message to other clients
            broadcast_message(decrypted_message, client_socket)

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")

    finally:
        # Cleanup on client disconnect
        client_socket.close()
        clients.remove(client_socket)
        del client_keys[client_socket]
        del client_ids[client_socket]
        print(f"Client {client_address} has been removed.")

        # Stop the server if no clients are connected
        if not clients:
            stop_server()


def stop_server():
    """
    Stop the server gracefully by closing all client connections.
    """
    print("Stopping server...")
    for client in clients:
        client.close()
    server_socket.close()
    print("Server stopped.")
    exit(0)  # Ensure the script stops execution


# Accept connections from clients
try:
    print("Server is listening for clients...")
    while True:
        client_socket, client_address = server_socket.accept()
        clients.append(client_socket)
        print(f"Client {client_address} connected.")
        threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()

except KeyboardInterrupt:
    # Handle server shutdown gracefully
    stop_server()
