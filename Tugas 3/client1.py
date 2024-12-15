import socket
from des import des_encrypt, des_decrypt
from rsa import RSA_Algorithm
import random

def generate_random_nonce():
    return random.randint(100000, 999999)
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

# Generate Nonce 1 and send it to Client 2
n1 = generate_random_nonce()
n1_str = str(n1)
encrypted_n1 = RSA_Algorithm.encrypt(n1_str, client2_public_key)
encrypted_n1_str=' '.join(map(str, encrypted_n1))
conn.sendall(encrypted_n1_str.encode())

# Received Nonce 1 and verify it with Generated Nonce !
received_n1 = conn.recv(1024).decode()
received_n1_list = list(map(int, received_n1.split(" ")))
decrypted_received_n1 = RSA_Algorithm.decrypt(received_n1_list, client1_private_key)

print()
# Verify Nonce 1
if n1_str == decrypted_received_n1:
    print(f"Generated {n1_str} == Received {decrypted_received_n1}")
    print("Nonce 1 verified.")
else:
    print("Nonce 1 verification failed.")
    conn.close()
    server_socket.close()
    print("Disconnected from the server.")

print()

# Receive Nonce 2 from Client 2 and send it back encrypted
n2 = conn.recv(1024).decode()
n2_list = list(map(int, n2.split(" ")))
decrypted_n2 = RSA_Algorithm.decrypt(n2_list, client1_private_key)

encrypted_n2 = RSA_Algorithm.encrypt(decrypted_n2, client2_public_key)
encrypted_n2_str=' '.join(map(str, encrypted_n2))

conn.sendall(encrypted_n2_str.encode())

# Secure communication begins
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
