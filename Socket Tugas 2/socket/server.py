import socket
from des import des_encrypt, des_decrypt  # Your custom DES functions

SERVER_IP = '127.0.0.1'
SERVER_PORT = 65432
KEY = "mysecretkey"  # Must be 8 characters for DES (56-bit DES)

# Set up the server socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen()
    print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

    conn, addr = server_socket.accept()
    with conn:
        print(f"Connected by {addr}")
        
        while True:
            # Receive encrypted message from the client
            encrypted_message = conn.recv(4096)  # Buffer size for longer messages
            if not encrypted_message:
                break  # Exit if no message is received (client disconnected)
            
            encrypted_bits = list(map(int, encrypted_message.decode()))
            print(f"Received encrypted message: {encrypted_message.decode()}")
            
            # Decrypt the message
            decrypted_message = des_decrypt(encrypted_bits, KEY)
            print(f"Decrypted message from client: {decrypted_message}")
            
            # Get server response
            response = input("Enter a response to send back to client: ")
            
            # Encrypt the response
            encrypted_response_bits = des_encrypt(response, KEY)
            encrypted_response = "".join(map(str, encrypted_response_bits))
            print(f"Sending encrypted response: {encrypted_response}")
            
            # Send encrypted response back to client
            conn.sendall(encrypted_response.encode())
