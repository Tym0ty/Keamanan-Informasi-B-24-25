import secrets
import math

class RSA_Algorithm:
    @staticmethod
    def is_prime(n):
        """
        Check if a number is a prime.
        :param n: The number to check.
        :return: True if prime, False otherwise.
        """
        if n <= 1:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    @staticmethod
    def generate_prime():
        """
        Generate a random prime number of 16 bits.
        :return: A 16-bit prime number.
        """
        while True:
            prime = secrets.randbits(16)  # Generate a random 16-bit number
            if RSA_Algorithm.is_prime(prime):
                return prime

    @staticmethod
    def generate_keypair():
        """
        Generate an RSA keypair.
        :return: A tuple containing the public key and private key.
        """
        # Generate two distinct primes p and q
        p = RSA_Algorithm.generate_prime()
        q = RSA_Algorithm.generate_prime()
        while p == q:  # Ensure p and q are not the same
            q = RSA_Algorithm.generate_prime()

        n = p * q  # Modulus
        phi = (p - 1) * (q - 1)  # Euler's totient function

        # Choose e such that 1 < e < phi and gcd(e, phi) == 1
        while True:
            e = secrets.randbelow(phi - 1) + 2  # Ensure e is at least 2
            if math.gcd(e, phi) == 1:
                break

        # Compute the modular multiplicative inverse of e mod phi
        d = pow(e, -1, phi)
        return ((n, e), (n, d))  # Public key and private key

    @staticmethod
    def encrypt(message, public_key):
        """
        Encrypt a message using the public key.
        :param message: The plaintext message as a string.
        :param public_key: The public key (n, e).
        :return: The encrypted message as a list of integers.
        """
        n, e = public_key
        encrypted_message = [pow(ord(char), e, n) for char in message]
        return encrypted_message

    @staticmethod
    def decrypt(encrypted_message, private_key):
        """
        Decrypt a message using the private key.
        :param encrypted_message: The encrypted message as a list of integers.
        :param private_key: The private key (n, d).
        :return: The decrypted message as a string.
        """
        n, d = private_key
        decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
        return decrypted_message

