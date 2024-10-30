import socket
from des import des_encrypt, des_decrypt  # Your custom DES functions

SERVER_IP = '127.0.0.1'
SERVER_PORT = 65432
KEY = "mysecretkey"  # Must be 8 characters for DES (56-bit DES)

# Set up the client socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((SERVER_IP, SERVER_PORT))
    
    while True:
        # Input message to send to server
        message = input("Enter a message to send to the server (or type 'exit' to quit): ")
        if message.lower() == 'exit':
            break  # Exit the loop if 'exit' is entered

        # Encrypt the message
        encrypted_message_bits = des_encrypt(message, KEY)
        encrypted_message = "".join(map(str, encrypted_message_bits))
        print(f"Sending encrypted message: {encrypted_message}")
        
        # Send encrypted message to the server
        client_socket.sendall(encrypted_message.encode())
        
        # Receive encrypted response from server
        encrypted_response = client_socket.recv(4096)  # Buffer size for longer messages
        encrypted_response_bits = list(map(int, encrypted_response.decode()))
        print(f"Received encrypted response: {encrypted_response.decode()}")
        
        # Decrypt the response
        decrypted_response = des_decrypt(encrypted_response_bits, KEY)
        print(f"Decrypted response from server: {decrypted_response}")
