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


client2_public_key = get_key_from_pka("client2_public_key")
client2_private_key = get_key_from_pka("client2_private_key")

client2_public_key = parse_key(client2_public_key)
client2_private_key = parse_key(client2_private_key)

print(f"Client2's Public Key: {client2_public_key}")
print(f"Client2's Private Key: {client2_private_key}")

client1_public_key = get_key_from_pka("client1_public_key")
client1_public_key = parse_key(client1_public_key)
print(f"Client1's Public Key: {client1_public_key}")

host = '127.0.0.1'
port = 65000
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))
print("Connected to the server.")

# Received client 1's nonce 1
n1 = client_socket.recv(1024).decode()
n1_list = list(map(int, n1.split(" ")))
decrypted_n1 = RSA_Algorithm.decrypt(n1_list, client2_private_key)
print(f"Decrypted N1: {decrypted_n1}")

# Sending nonce 1 to client 1
encrypted_n1 = RSA_Algorithm.encrypt(decrypted_n1, client1_public_key)
encrypted_n1_str=' '.join(map(str, encrypted_n1))
client_socket.sendall(encrypted_n1_str.encode())

# Generate nonce 2 and send it to client 1
n2 = generate_random_nonce()
n2_str = str(n2)
encrypted_n2 = RSA_Algorithm.encrypt(n2_str, client1_public_key)
encrypted_n2_str=' '.join(map(str, encrypted_n2))
client_socket.sendall(encrypted_n2_str.encode())

# Received Nonce 2 and compare it with generated Nonce 2
received_n2 = client_socket.recv(1024).decode()
received_n2_list = list(map(int, received_n2.split(" ")))
decrypted_received_n2 = RSA_Algorithm.decrypt(received_n2_list, client2_private_key)

print()
# Verify Nonce 2
if n2_str == decrypted_received_n2:
    print(f"Generated {n2_str} == Received {decrypted_received_n2}")
    print("Nonce 2 verified.")
else:
    print("Nonce 2 verification failed.")
    client_socket.close()
    print("Disconnected from the server.")

print()

# Secure communication begins
while True:
    response = client_socket.recv(1024).decode()

    delimiter = "|"
    message_response,des_key_response=response.split(delimiter)
    message_response_list = list(map(int,message_response.split(" ")))

    print()

    decrypted_response = des_decrypt(list(map(int, message_response_list)), des_key)
    print(f"Pesan dari Client 1: {decrypted_response}")
    print()
 

    print('Tulis "exit" untuk keluar.')
    message = input("Masukkan Pesan : ")
    if message.lower() == 'exit':
        client_socket.send(message.encode())
        break
    
    message_response,des_key_response=response.split(delimiter)

    des_key_response_list = list(map(int, des_key_response.split(" ")))
    decrypted_des_key=RSA_Algorithm.decrypt(des_key_response_list,client2_private_key)
    des_key_response_list2 = list(map(int, decrypted_des_key.split(" ")))

    final_decrypted_des_key = RSA_Algorithm.decrypt(des_key_response_list2, client1_public_key)

    if message_response == 'exit':
        print("Server has disconnected.")
        break

    
    encrypted_message = des_encrypt(message, des_key)
    encrypted_message_str = ''.join(map(str, encrypted_message))
    
    print("Encrypted message sent.")

    payload=encrypted_message_str

    client_socket.sendall(payload.encode())

client_socket.close()
print("Disconnected from the server.")


