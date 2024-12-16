import socket
from des import des_encrypt, des_decrypt
from rsa import RSA_Algorithm
import random

def generate_random_nonce():
    return random.randint(100000, 999999)

# Generate RSA keys for Client2
client2_public_key, client2_private_key = RSA_Algorithm.generate_keypair()
print()
print(f"Client2's Public Key: {client2_public_key}")
print(f"Client2's Private Key: {client2_private_key}")

PKA_HOST = "localhost"
PKA_PORT = 65432

def register_with_pka(identifier, public_key):
    try:
        pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka_socket.connect((PKA_HOST, PKA_PORT))
        message = f"REGISTER;{identifier};{public_key[0]},{public_key[1]}"
        pka_socket.sendall(message.encode('utf-8'))
        response = pka_socket.recv(1024).decode('utf-8')

        # Parse the PKA public key from the response
        if response.startswith("REGISTERED;"):
            pka_public_key_str = response.split(';')[1]
            n, e = map(int, pka_public_key_str.split(','))
            pka_public_key = (n, e)
            print()
            print(f"Received PKA Public Key: {pka_public_key}")
            return pka_public_key
        else:
            raise ValueError("Invalid response from PKA")
    finally:
        pka_socket.close()

def request_key_from_pka(identifier, pka_public_key):
    try:
        pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka_socket.connect((PKA_HOST, PKA_PORT))
        message = f"REQUEST;{identifier};"
        pka_socket.sendall(message.encode('utf-8'))
        encrypted_response = pka_socket.recv(1024).decode('utf-8')

        # Decrypt the response using the PKA public key
        encrypted_key_list = list(map(int, encrypted_response.split(' ')))
        decrypted_key_str = RSA_Algorithm.decrypt(encrypted_key_list, pka_public_key)
        print()
        print(f"Decrypted Public Key for {identifier}: {decrypted_key_str}")
        return parse_key(decrypted_key_str)
    finally:
        pka_socket.close()

def parse_key(key_str):
    key_formatted = key_str.strip("() ").replace(" ", "")
    n, e = map(int, key_formatted.split(','))
    return (n, e)

# Register Client2's public key with PKA and get PKA's public key
pka_public_key = register_with_pka("client2_public_key", client2_public_key)

# Request Client1's public key from PKA
encrypted_client1_public_key = request_key_from_pka("client1_public_key", pka_public_key)
client1_public_key = encrypted_client1_public_key
print()
print(f"Client1's Public Key: {client1_public_key}")

host = '127.0.0.1'
port = 65000
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))
print("Connected to the server.")

# Step 1: Receive and decrypt Nonce 1
n1 = client_socket.recv(1024).decode()
n1_list = list(map(int, n1.split(" ")))
decrypted_n1 = RSA_Algorithm.decrypt(n1_list, client2_private_key)
print()
print(f"Decrypted N1: {decrypted_n1}")

# Step 2: Encrypt and send Nonce 1 back to Client1
encrypted_n1 = RSA_Algorithm.encrypt(decrypted_n1, client1_public_key)
encrypted_n1_str = ' '.join(map(str, encrypted_n1))
client_socket.sendall(encrypted_n1_str.encode())

# Step 3: Generate, encrypt, and send Nonce 2 to Client1
n2 = generate_random_nonce()
encrypted_n2 = RSA_Algorithm.encrypt(str(n2), client1_public_key)
encrypted_n2_str = ' '.join(map(str, encrypted_n2))
client_socket.sendall(encrypted_n2_str.encode())

# Step 4: Receive and decrypt Nonce 2 for verification
received_n2 = client_socket.recv(1024).decode()
received_n2_list = list(map(int, received_n2.split(" ")))
decrypted_received_n2 = RSA_Algorithm.decrypt(received_n2_list, client2_private_key)

# Verify Nonce 2
if str(n2) == decrypted_received_n2:
    print()
    print(f"Generated {n2} == Received {decrypted_received_n2}")
    print("Nonce 2 verified.")
else:
    print()
    print("Nonce 2 verification failed.")
    client_socket.close()
    print("Disconnected from the server.")
    exit()

# Secure communication begins
while True:
    response = client_socket.recv(1024).decode()
    delimiter = "|"
    message_response, des_key_response = response.split(delimiter)

    # DES key
    des_key_response_list = list(map(int, des_key_response.split(" ")))
    decrypted_des_key=RSA_Algorithm.decrypt(des_key_response_list,client2_private_key)
    des_key_response_list2 = list(map(int, decrypted_des_key.split(" ")))
    final_decrypted_des_key = RSA_Algorithm.decrypt(des_key_response_list2, client1_public_key)

    print()
    print(f"Received DES Key: {final_decrypted_des_key}")

    # Message
    message_response_list = list(map(int, message_response.split(" ")))

    decrypted_response = des_decrypt(message_response_list, final_decrypted_des_key)
    print()
    print(f"Message from Client 1: {decrypted_response}")
    print()

    print('Type "exit" to disconnect.')
    message = input("Enter message: ")
    if message.lower() == 'exit':
        client_socket.send(message.encode())
        break

    encrypted_message = des_encrypt(message, final_decrypted_des_key)
    encrypted_message_str = ' '.join(map(str, encrypted_message))
    print()
    print("Encrypted message sent.")
    client_socket.sendall(encrypted_message_str.encode())

client_socket.close()
print()
print("Disconnected from the server.")
