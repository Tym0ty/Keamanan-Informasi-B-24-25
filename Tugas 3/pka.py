import socket
import threading
from rsa import RSA_Algorithm

class PKA:
    def __init__(self):
        self.public_keys = {}  # Dictionary to store public keys

        # Generate RSA key pair for PKA itself
        self.pka_public_key, self.pka_private_key = RSA_Algorithm.generate_keypair()
        print(f"PKA Public Key: {self.pka_public_key}")
        print(f"PKA Private Key: {self.pka_private_key}")

    def handle_client(self, client_socket):
        try:
            data = client_socket.recv(1024).decode('utf-8')
            print()
            print(f"Received data: {data}")

            if not data:
                return

            # Parse incoming message
            parts = data.split(';')
            action = parts[0]

            if action == 'REGISTER':
                identifier, key = parts[1], parts[2]
                self.public_keys[identifier] = key
                print(f"{identifier}'s public key registered: {key}")

                # Send PKA's public key as response
                response = f"REGISTERED;{self.pka_public_key[0]},{self.pka_public_key[1]}"
                print(f"Sending PKA public key to client: {response}")
                client_socket.sendall(response.encode('utf-8'))

            elif action == 'REQUEST':
                identifier = parts[1]
                print()
                print(f"Request for public key of: {identifier}")

                if identifier in self.public_keys:
                    target_key = self.public_keys[identifier]
                    print()
                    print(f"Found public key for {identifier}: {target_key}")

                    # Encrypt the target key with PKA's private key
                    encrypted_key = RSA_Algorithm.encrypt(target_key, self.pka_private_key)
                    encrypted_key_str = ' '.join(map(str, encrypted_key))
                    print()
                    print(f"Sending encrypted public key for {identifier}: {encrypted_key_str}")
                    client_socket.sendall(encrypted_key_str.encode('utf-8'))
                else:
                    response = "NOT_FOUND"
                    print()
                    print(f"Public key for {identifier} not found.")
                    client_socket.sendall(response.encode('utf-8'))

        except Exception as e:
            print()
            print(f"Error: {e}")
        finally:
            client_socket.close()
        

    def start_server(self):
        host = "0.0.0.0"
        port = 65432

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(5)
        print()
        print(f"PKA Server started on {host}:{port}")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                print()
                print(f"Connection from {addr}")
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()
        except KeyboardInterrupt:
            print("\nServer interrupted by user. Shutting down...")
        finally:
            server_socket.close()
            print()
            print("Server socket closed. Goodbye!")

if __name__ == "__main__":
    pka = PKA()
    pka.start_server()
