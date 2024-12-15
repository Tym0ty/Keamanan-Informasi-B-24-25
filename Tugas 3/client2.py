import socket
import threading
from des import des_encrypt, des_decrypt
from rsa import RSA_Algorithm

# Generate a random DES key
des_key = "mysecret"  # 8-byte key (must be 8 characters for DES)
print(f"Generated DES key for Client: {des_key}")

PKA_HOST = "localhost"  
PKA_PORT = 65432       

def get_key_from_pka(role):
    try:
        pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka_socket.connect((PKA_HOST, PKA_PORT))
        pka_socket.sendall(role.encode('utf-8'))  
        key = pka_socket.recv(1024).decode('utf-8')
        return key  
    finally:
        pka_socket.close()

def parse_key(key_str):
    key_formatted = key_str.strip("()").replace(" ", "")
    n, e = map(int, key_formatted.split(','))
    return (n, e)


client2_public_key = get_key_from_pka("client2_public_key")
client2_public_key = parse_key(client2_public_key)
client2_private_key = get_key_from_pka("client2_private_key")
client2_private_key = parse_key(client2_private_key)
print(f"Client2's Public Key: {client2_public_key}")
print(f"Client2's Private Key: {client2_private_key}")

client1_public_key = get_key_from_pka("client1_public_key")
client1_public_key = parse_key(client1_public_key)
print(f"Client1's Public Key: {client1_public_key}")

# Connect to client
host = '127.0.0.1'
port = 65000
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))
print("Connected to the server.")

while True:
    print('Tulis "exit" untuk keluar.')
    # Get message input from the user
    message = input("Masukkan Pesan : ")
    if message.lower() == 'exit':
        client_socket.send(message.encode())
        break
    
    # Receive the server's response
    response = client_socket.recv(1024).decode()
       
    delimiter = "|"
    message_response,des_key_response=response.split(delimiter)

    # Convert `des_key_response` back into a list of integers
    des_key_response_list = list(map(int, des_key_response.split(" ")))

    # Decrypt the des_key using client2's private key
    decrypted_des_key=RSA_Algorithm.decrypt(des_key_response_list,client2_private_key)

    des_key_response_list2 = list(map(int, decrypted_des_key.split(" ")))

    # Decrypt the des_key again using clien1's public key
    final_decrypted_des_key = RSA_Algorithm.decrypt(des_key_response_list2, client1_public_key)


    if message_response == 'exit':
        print("Server has disconnected.")
        break


    message_response_list = list(map(int,message_response.split(" ")))

    print()

    decrypted_response = des_decrypt(list(map(int, message_response_list)), des_key)
    print(f"Pesan dari Client 1: {decrypted_response}")
    print()
    # Encrypt the message using DES
    encrypted_message = des_encrypt(message, des_key)
    encrypted_message_str = ''.join(map(str, encrypted_message))
    
    print("Encrypted message sent.")

    payload=encrypted_message_str

    client_socket.sendall(payload.encode())

client_socket.close()
print("Disconnected from the server.")


