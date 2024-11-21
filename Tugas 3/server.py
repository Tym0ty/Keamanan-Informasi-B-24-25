import socket
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
server_socket.listen(1)  # Allow 1 client

print("Public Key Authority is listening...")

# Accept connection from Client 1
client_socket1, client_address1 = server_socket.accept()
print(f"Client 1 connected from {client_address1}")

# Send the public key of the PKA to Client 1
client_socket1.send(f"{public_key[0]},{public_key[1]}".encode())
print("Public key sent to Client 1.")

# Receive encrypted DES key from Client 1
encrypted_des_key1 = client_socket1.recv(4096).decode()
encrypted_des_key1 = list(map(int, encrypted_des_key1.split(',')))
des_key1 = RSA_Algorithm.decrypt(encrypted_des_key1, private_key)
print(f"Received and decrypted DES key from Client 1: {des_key1}")

# Communication loop with only Client 1
while True:
    # Receive encrypted message from Client 1
    encrypted_message1 = client_socket1.recv(4096).decode()
    if encrypted_message1 == 'exit':
        print("Client 1 has disconnected.")
        break
    encrypted_message_bits1 = list(map(int, encrypted_message1))
    print(f"Encrypted message from Client 1: {encrypted_message_bits1}")

    # Decrypt message using DES key of Client 1
    decrypted_message1 = des_decrypt(encrypted_message_bits1, des_key1)
    print(f"Decrypted message from Client 1: {decrypted_message1}")

    # Respond to Client 1 using DES encryption
    response1 = input("Enter response to Client 1: ")
    encrypted_response1 = des_encrypt(response1, des_key1)
    encrypted_response_str1 = ''.join(map(str, encrypted_response1))
    client_socket1.send(encrypted_response_str1.encode())

# Close the connection
client_socket1.close()
server_socket.close()
