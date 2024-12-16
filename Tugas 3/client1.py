import socket
import random
from des import des_encrypt, des_decrypt
from rsa import RSA_Algorithm

def generate_random_nonce():
    return random.randint(100000, 999999)

# Generate RSA keys for Client 1
client1_public_key, client1_private_key = RSA_Algorithm.generate_keypair()
# Corrected print statements using the actual emoji
print()
print(f"Client1's Public Key: {client1_public_key}")
print(f"Client1's Private Key: {client1_private_key}")


PKA_HOST = "localhost"
PKA_PORT = 65432

# To store PKA's public key
pka_public_key = None

def register_with_pka(identifier, public_key):
    global pka_public_key
    try:
        pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka_socket.connect((PKA_HOST, PKA_PORT))

        # Send registration request
        message = f"REGISTER;{identifier};{public_key[0]},{public_key[1]}"
        pka_socket.sendall(message.encode('utf-8'))

        # Receive PKA's public key
        response = pka_socket.recv(1024).decode('utf-8')
        action, pka_key_str = response.split(';')

        if action == "REGISTERED":
            n, e = map(int, pka_key_str.split(','))
            pka_public_key = (n, e)
            print()
            print(f"Received PKA Public Key: {pka_public_key}")
        else:
            print()
            print("Registration failed.")
    finally:
        pka_socket.close()

def request_key_from_pka(identifier):
    global pka_public_key
    if not pka_public_key:
        raise ValueError("PKA public key is not available. Please register first.")

    try:
        pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka_socket.connect((PKA_HOST, PKA_PORT))

        # Send request for public key
        message = f"REQUEST;{identifier};"
        pka_socket.sendall(message.encode('utf-8'))

        # Receive encrypted response
        encrypted_response = pka_socket.recv(1024).decode('utf-8')

        # Decrypt the response using PKA's public key
        encrypted_key_list = list(map(int, encrypted_response.split(' ')))
        decrypted_key = RSA_Algorithm.decrypt(encrypted_key_list, pka_public_key)
        print()
        print(f"Decrypted Public Key for {identifier}: {decrypted_key}")
        
        return tuple(map(int, decrypted_key.split(',')))
    finally:
        pka_socket.close()

# Register client1's public key with PKA
register_with_pka("client1_public_key", client1_public_key)

# DES key for encryption
des_key = "mysecret"  # 8-byte key (must be 8 characters for DES)
print()
print(f"DES key for Client: {des_key}")

host = '127.0.0.1'
port = 65000
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(1)

conn, address = server_socket.accept()
print()
print(f"Connection from: {address}")

# Request client2's public key from PKA
client2_public_key = request_key_from_pka("client2_public_key")
print()
print(f" Client2's Public Key: {client2_public_key}")

# Step 1: Generate and send nonce N1 to Client 2
n1 = generate_random_nonce()
n1_str = str(n1)
encrypted_n1 = RSA_Algorithm.encrypt(n1_str, client2_public_key)
encrypted_n1_str = ' '.join(map(str, encrypted_n1))
conn.sendall(encrypted_n1_str.encode())

# Step 2: Receive and verify Nonce 1
received_n1 = conn.recv(1024).decode()
received_n1_list = list(map(int, received_n1.split(" ")))
decrypted_received_n1 = RSA_Algorithm.decrypt(received_n1_list, client1_private_key)

if n1_str == decrypted_received_n1:
    print()
    print(f"Nonce 1 verified: {n1_str} == {decrypted_received_n1}")
else:
    print()
    print("Nonce 1 verification failed.")
    conn.close()
    server_socket.close()
    exit()

# Step 3: Receive Nonce 2 from Client 2 and send it back encrypted
n2 = conn.recv(1024).decode()
n2_list = list(map(int, n2.split(" ")))
decrypted_n2 = RSA_Algorithm.decrypt(n2_list, client1_private_key)

encrypted_n2 = RSA_Algorithm.encrypt(decrypted_n2, client2_public_key)
encrypted_n2_str = ' '.join(map(str, encrypted_n2))
conn.sendall(encrypted_n2_str.encode())

# Secure communication begins
while True:
    print('Type "exit" to disconnect.')
    message = input("Enter message: ")
    if message.lower() == 'exit':
        conn.send(message.encode())
        break

    encrypted_message = des_encrypt(message, des_key)
    encrypted_message_str = ' '.join(map(str, encrypted_message))

    encrypted_des_key = RSA_Algorithm.encrypt(des_key, client1_private_key)
    encrypted_des_key_str = ' '.join(map(str, encrypted_des_key))
    final_encrypted_des_key = RSA_Algorithm.encrypt(encrypted_des_key_str, client2_public_key)
    final_encrypted_des_key_str = ' '.join(map(str, final_encrypted_des_key))

    delimiter = "|"
    payload = encrypted_message_str + delimiter + final_encrypted_des_key_str
    conn.sendall(payload.encode())

    response = conn.recv(1024).decode()
    if response.lower() == 'exit':
        print()
        print("Client 2 has disconnected.")
        break

    encrypted_response_list = list(map(int, response.split(" ")))
    decrypted_response = des_decrypt(encrypted_response_list, des_key)
    print()
    print(f"Message from Client 2: {decrypted_response}")
    print()

conn.close()
server_socket.close()
print("Disconnected from the server.")
