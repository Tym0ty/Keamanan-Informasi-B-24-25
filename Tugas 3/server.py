import socket
from des import des_decrypt, des_encrypt
from rsa import RSA_Algorithm

# Generate RSA keypair
public_key, private_key = RSA_Algorithm.generate_keypair()
print(f"Server Public Key: {public_key}")
print(f"Server Private Key: {private_key}")

# Server setup
host = '127.0.0.1'
port = 65432
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(1)

print("Server is listening...")

client_socket, client_address = server_socket.accept()
print(f"Connection established with {client_address}")

# Send public key to the client
client_socket.send(f"{public_key[0]},{public_key[1]}".encode())
print("Public key sent to the client.")

# Receive encrypted DES key from the client
encrypted_des_key = client_socket.recv(4096).decode()
encrypted_des_key = list(map(int, encrypted_des_key.split(',')))
des_key = RSA_Algorithm.decrypt(encrypted_des_key, private_key)
print(f"Received and decrypted DES key: {des_key}")

while True:
    # Receive encrypted message from the client
    encrypted_message = client_socket.recv(4096).decode()
    if encrypted_message == 'exit':
        print("Client has disconnected.")
        break

    encrypted_message_bits = list(map(int, encrypted_message))
    print(f"Encrypted message received: {encrypted_message}")

    # Decrypt the message using DES
    decrypted_message = des_decrypt(encrypted_message_bits, des_key)
    print(f"Decrypted message: {decrypted_message}")

    # Respond to the client
    response = input("Enter response to client: ")
    if response.lower() == 'exit':
        client_socket.send(response.encode())
        break

    # Encrypt response using DES
    encrypted_response = des_encrypt(response, des_key)
    encrypted_response_str = ''.join(map(str, encrypted_response))
    
    # Print the encrypted and decrypted response on the server side
    print(f"Encrypted response: {encrypted_response_str}")
    print(f"Decrypted response: {response}")
    
    # Send encrypted response back to the client
    client_socket.send(encrypted_response_str.encode())

# Close the connection
client_socket.close()
server_socket.close()
