# Permutasi awal 
IP = [58, 50, 42, 34, 26, 18, 10, 2, 
      60, 52, 44, 36, 28, 20, 12, 4, 
      62, 54, 46, 38, 30, 22, 14, 6, 
      64, 56, 48, 40, 32, 24, 16, 8, 
      57, 49, 41, 33, 25, 17, 9, 1, 
      59, 51, 43, 35, 27, 19, 11, 3, 
      61, 53, 45, 37, 29, 21, 13, 5, 
      63, 55, 47, 39, 31, 23, 15, 7]

# Permutasi invers 
FP = [40, 8, 48, 16, 56, 24, 64, 32, 
      39, 7, 47, 15, 55, 23, 63, 31, 
      38, 6, 46, 14, 54, 22, 62, 30, 
      37, 5, 45, 13, 53, 21, 61, 29, 
      36, 4, 44, 12, 52, 20, 60, 28, 
      35, 3, 43, 11, 51, 19, 59, 27, 
      34, 2, 42, 10, 50, 18, 58, 26, 
      33, 1, 41, 9, 49, 17, 57, 25]

# Tabel ekspansi 
E = [32, 1, 2, 3, 4, 5, 4, 5, 
     6, 7, 8, 9, 8, 9, 10, 11, 
     12, 13, 12, 13, 14, 15, 16, 17, 
     16, 17, 18, 19, 20, 21, 20, 21, 
     22, 23, 24, 25, 24, 25, 26, 27, 
     28, 29, 28, 29, 30, 31, 32, 1]

# Tabel permutasi P 
P = [16, 7, 20, 21, 29, 12, 28, 17, 
     1, 15, 23, 26, 5, 18, 31, 10, 
     2, 8, 24, 14, 32, 27, 3, 9, 
     19, 13, 30, 6, 22, 11, 4, 25]

# Tabel S-boxes
S_BOX = [
    # S1
    [[12, 7, 10, 1, 5, 11, 13, 0, 8, 9, 6, 3, 2, 14, 15, 4],
     [2, 11, 1, 9, 0, 5, 15, 8, 10, 7, 12, 14, 13, 4, 6, 3],
     [5, 1, 13, 8, 12, 9, 3, 14, 15, 2, 6, 11, 7, 0, 10, 4],
     [13, 12, 8, 6, 5, 14, 0, 11, 2, 10, 3, 7, 15, 9, 4, 1]],

    # S2
    [[6, 2, 14, 13, 1, 9, 10, 4, 3, 15, 12, 0, 11, 8, 5, 7],
     [13, 10, 1, 7, 12, 2, 5, 8, 14, 3, 9, 4, 11, 0, 6, 15],
     [4, 6, 10, 0, 9, 13, 3, 12, 11, 14, 8, 1, 15, 7, 2, 5],
     [7, 9, 2, 4, 0, 14, 5, 6, 12, 11, 15, 3, 8, 1, 13, 10]],

    # S3
    [[10, 4, 13, 0, 8, 15, 5, 7, 1, 11, 14, 12, 9, 6, 2, 3],
     [7, 3, 0, 6, 1, 12, 9, 13, 10, 15, 4, 14, 11, 8, 5, 2],
     [13, 7, 6, 1, 9, 11, 3, 14, 0, 8, 12, 5, 10, 4, 2, 15],
     [3, 0, 10, 5, 12, 7, 14, 9, 4, 1, 6, 11, 15, 2, 13, 8]],

    # S4
    [[9, 5, 2, 12, 15, 1, 8, 6, 14, 0, 11, 13, 7, 3, 4, 10],
     [11, 14, 6, 3, 9, 8, 7, 4, 1, 12, 2, 10, 5, 15, 0, 13],
     [1, 12, 11, 5, 4, 15, 2, 14, 10, 7, 0, 9, 3, 6, 13, 8],
     [15, 9, 0, 11, 13, 6, 3, 1, 5, 12, 8, 4, 7, 2, 14, 10]],

    # S5
    [[1, 3, 9, 14, 5, 0, 12, 7, 10, 4, 2, 8, 11, 6, 13, 15],
     [2, 9, 12, 6, 15, 1, 4, 3, 7, 10, 0, 11, 5, 8, 13, 14],
     [8, 5, 7, 4, 11, 0, 14, 12, 13, 3, 6, 2, 1, 9, 15, 10],
     [11, 10, 3, 8, 13, 15, 2, 1, 9, 0, 5, 14, 12, 6, 7, 4]],

    # S6
    [[7, 8, 4, 0, 2, 15, 10, 11, 1, 9, 13, 12, 5, 6, 14, 3],
     [9, 1, 6, 7, 12, 0, 14, 3, 11, 13, 2, 5, 10, 8, 15, 4],
     [15, 12, 1, 14, 9, 2, 3, 10, 7, 0, 11, 5, 6, 13, 4, 8],
     [0, 5, 8, 15, 7, 11, 6, 4, 13, 9, 14, 2, 10, 12, 1, 3]],

    # S7
    [[4, 11, 5, 14, 13, 1, 2, 9, 0, 7, 6, 8, 12, 3, 15, 10],
     [6, 10, 12, 3, 0, 7, 9, 14, 11, 1, 5, 2, 8, 13, 15, 4],
     [10, 8, 7, 11, 5, 4, 12, 15, 1, 3, 0, 6, 2, 9, 14, 13],
     [5, 2, 14, 13, 3, 0, 8, 12, 9, 15, 10, 6, 4, 11, 7, 1]],

    # S8
    [[5, 1, 12, 14, 6, 9, 3, 2, 0, 8, 7, 13, 4, 10, 11, 15],
     [3, 13, 2, 11, 5, 0, 8, 6, 9, 14, 10, 7, 12, 4, 15, 1],
     [14, 7, 1, 4, 8, 10, 12, 13, 0, 9, 11, 6, 15, 5, 3, 2],
     [11, 3, 0, 12, 2, 15, 6, 5, 1, 13, 14, 8, 7, 4, 9, 10]]
]

# Shift key schedule
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 
                  1, 2, 2, 2, 2, 2, 2, 1]

# Tabel permutasi kunci
PC1 = [57, 49, 41, 33, 25, 17, 9, 
       1, 58, 50, 42, 34, 26, 18, 
       10, 2, 59, 51, 43, 35, 27, 
       19, 11, 3, 60, 52, 44, 36, 
       63, 55, 47, 39, 31, 23, 15, 
       7, 62, 54, 46, 38, 30, 22, 
       14, 6, 61, 53, 45, 37, 29, 
       21, 13, 5, 28, 20, 12, 4]

# Permutasi kunci kompresi 
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 
       15, 6, 21, 10, 23, 19, 12, 4, 
       26, 8, 16, 7, 27, 20, 13, 2, 
       41, 52, 31, 37, 47, 55, 30, 40, 
       51, 45, 33, 48, 44, 49, 39, 56, 
       34, 53, 46, 42, 50, 36, 29, 32]

def permutate(block, table):
    """ Function to permutate a block of bits based on a given table """
    return [block[x - 1] for x in table]

def xor(bits1, bits2):
    """ Function to XOR two bit arrays """
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def shift_left(bits, n):
    """ Function to shift a list of bits to the left by n places """
    return bits[n:] + bits[:n]

def sbox_substitution(bits):
    """ Function to substitute 48-bit input using the 8 S-Boxes """
    result = []
    for i in range(8):
        block = bits[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        result += [int(x) for x in f'{S_BOX[i][row][col]:04b}']
    return result

def feistel_function(right, subkey):
    """ The DES Feistel function """
    expanded_right = permutate(right, E)
    temp = xor(expanded_right, subkey)
    substituted = sbox_substitution(temp)
    return permutate(substituted, P)

def generate_keys(key):
    """ Function to generate 16 subkeys """
    key = permutate(key, PC1)
    left, right = key[:28], key[28:]
    subkeys = []
    for shift in SHIFT_SCHEDULE:
        left = shift_left(left, shift)
        right = shift_left(right, shift)
        subkeys.append(permutate(left + right, PC2))
    return subkeys

def des_encrypt_block(block, key):
    """ Function to encrypt a 64-bit block using DES """
    block = permutate(block, IP)
    left, right = block[:32], block[32:]
    subkeys = generate_keys(key)
    for subkey in subkeys:
        temp = right
        right = xor(left, feistel_function(right, subkey))
        left = temp
    return permutate(right + left, FP)

def des_decrypt_block(block, key):
    """ Function to decrypt a 64-bit block using DES """
    block = permutate(block, IP)
    left, right = block[:32], block[32:]
    subkeys = generate_keys(key)[::-1]
    for subkey in subkeys:
        temp = right
        right = xor(left, feistel_function(right, subkey))
        left = temp
    return permutate(right + left, FP)

def string_to_bit_array(text):
    """ Convert string to a list of bits """
    bit_array = []
    for char in text:
        binval = bin(ord(char))[2:].rjust(8, '0')
        bit_array += [int(x) for x in binval]
    return bit_array

def bit_array_to_string(bit_array):
    """ Convert list of bits to string """
    text = ''
    for i in range(0, len(bit_array), 8):
        byte = bit_array[i:i+8]
        text += chr(int(''.join([str(x) for x in byte]), 2))
    return text

def pad_bit_array(bit_array):
    """ Pad bit array to make sure its length is a multiple of 64 """
    padding_len = 64 - (len(bit_array) % 64)
    return bit_array + [0] * padding_len

def des_encrypt(text, key):
    """ Function to encrypt a text using DES """
    bit_array = string_to_bit_array(text)
    bit_array = pad_bit_array(bit_array)
    key = pad_bit_array(string_to_bit_array(key))[:64] 
    encrypted_bits = []
    for i in range(0, len(bit_array), 64):
        block = bit_array[i:i+64]
        encrypted_bits += des_encrypt_block(block, key)
    return encrypted_bits

def des_decrypt(cipher_bits, key):
    """ Function to decrypt a cipher bits using DES """
    key = pad_bit_array(string_to_bit_array(key))[:64]  
    decrypted_bits = []
    for i in range(0, len(cipher_bits), 64):
        block = cipher_bits[i:i+64]
        decrypted_bits += des_decrypt_block(block, key)
    return bit_array_to_string(decrypted_bits)


plain_text = "Hello World"
key = "Rahasia"

print("Plaintext:", plain_text)

# Enkripsi
cipher_bits = des_encrypt(plain_text, key)
print("Ciphertext (bit array):", cipher_bits)

# Dekripsi
decrypted_text = des_decrypt(cipher_bits, key)
print("Decrypted text:", decrypted_text)