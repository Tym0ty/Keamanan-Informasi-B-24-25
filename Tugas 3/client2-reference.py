import socket
import threading
from des import des_encrypt, des_decrypt
from rsa import RSA_Algorithm

# Generate a random DES key
des_key = "mysecret"  # 8-byte key (must be 8 characters for DES)
print(f"Generated DES key for Client: {des_key}")

# Connect to the server (PKA)
host = '127.0.0.1'
port = 65432
pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
pka_socket.connect((host, port))
print("Connected to the server.")

# Receive public key from the server
public_key_str = pka_socket.recv(1024).decode()
n, e = map(int, public_key_str.split(','))
public_key = (n, e)
print(f"Public key received from the server: {public_key}")

pka_socket.close()
print("Disconnected from the server.")

def listen_for_messages():
    """
    Continuously listen for messages from the server.
    """
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            # Decrypt the received message using DES
            decrypted_message = des_decrypt(list(map(int, message.split(','))), des_key)
            print(f"{decrypted_message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Start a thread to listen for messages
threading.Thread(target=listen_for_messages, daemon=True).start()

# Send messages to the server
while True:
    # Input message from user
    message = input("")
    if message.lower() == 'exit':
        client_socket.send(message.encode())
        break

    # Encrypt the message using DES
    encrypted_message = des_encrypt(message, des_key)
    encrypted_message_str = ','.join(map(str, encrypted_message))
    client_socket.send(encrypted_message_str.encode())
    print("Encrypted message sent to the server.")

# Close the connection
client_socket.close()
print("Disconnected from the server.")
