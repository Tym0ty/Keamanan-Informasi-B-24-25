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

client1_public_key = get_key_from_pka("client1_public_key")
client1_private_key = get_key_from_pka("client1_private_key")

client1_public_key = parse_key(client1_public_key)
client1_private_key = parse_key(client1_private_key)

print(f"Client1's Public Key: {client1_public_key}")
print(f"Client1's Private Key: {client1_private_key}")

client2_public_key = get_key_from_pka("client2_public_key")
client2_public_key = parse_key(client2_public_key)
print(f"Client2's Public Key: {client2_public_key}")

host = '127.0.0.1'
port = 65000
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(1)

conn, address = server_socket.accept()
print("Connection from:", address)

while True:
    print('Tulis "exit" untuk keluar.')
    message = input("Masukkan Pesan : ")
    if message.lower() == 'exit':
        conn.send(message.encode())
        break

    encrypted_message = des_encrypt(message, des_key)
    encrypted_message_str = ' '.join(map(str, encrypted_message))
    
    print("Encrypted message sent.")

    encrypted_des_key = RSA_Algorithm.encrypt(des_key, client1_private_key)
    encrypted_des_key_str = ' '.join(map(str, encrypted_des_key))
    final_encrypted_des_key = RSA_Algorithm.encrypt(encrypted_des_key_str, client2_public_key)

    final_encrypted_des_key_str = ' '.join(map(str, final_encrypted_des_key))

    delimiter = "|"
    payload=encrypted_message_str + delimiter + final_encrypted_des_key_str

    conn.sendall(payload.encode())

    response = conn.recv(1024).decode()

    if response == 'exit':
        print("Server has disconnected.")
        break

    message_response_list = list(map(int,response.split(" ")))
    print()
    decrypted_response = des_decrypt(list(map(int, response)), des_key)
    print(f"Pesan dari Client 2: {decrypted_response}")
    print()
conn.close()
server_socket.close()
print("Disconnected from the server.")
