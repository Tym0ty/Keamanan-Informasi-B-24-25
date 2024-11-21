import socket
from des import des_encrypt, des_decrypt
from rsa import RSA_Algorithm

# Generate a random DES key
des_key = "mysecret"  # 8-byte key (must be 8 characters for DES)
print(f"Generated DES key for Client 1: {des_key}")

# Connect to the server (PKA)
host = '127.0.0.1'
port = 65432
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))
print("Client 1 connected to the server.")

# Receive public key from the server
public_key_str = client_socket.recv(1024).decode()
n, e = map(int, public_key_str.split(','))
public_key = (n, e)
print(f"Public key received from the server: {public_key}")

# Encrypt the DES key using the server's public key
encrypted_des_key = RSA_Algorithm.encrypt(des_key, public_key)
encrypted_des_key_str = ','.join(map(str, encrypted_des_key))
client_socket.send(encrypted_des_key_str.encode())
print("Encrypted DES key sent to the server.")

while True:
    # Get message input from the user
    message = input("Enter message to send to the server (or type 'exit' to quit): ")
    if message.lower() == 'exit':
        client_socket.send(message.encode())
        break

    # Encrypt the message using DES
    encrypted_message = des_encrypt(message, des_key)
    encrypted_message_str = ''.join(map(str, encrypted_message))
    client_socket.send(encrypted_message_str.encode())
    print("Encrypted message sent to the server.")

    # Receive the server's response
    response = client_socket.recv(1024).decode()
    if response == 'exit':
        print("Server has disconnected.")
        break
    print(f"Server response: {response}")
    decrypted_response = des_decrypt(list(map(int, response)), des_key)
    print(f"Decrypted response: {decrypted_response}")

# Close the connection
client_socket.close()
