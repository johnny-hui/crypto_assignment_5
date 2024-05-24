import math
from utility.init import ECB
from utility.utilities import process_subkey_generation, pad_block

# CONSTANTS
BLOCK_SIZE = 8
ROUNDS = 2
DEFAULT_ROUND_KEYS = [
    0xdddddddd, 0xeeeeeeee, 0xaaaaaaaa, 0xdddddddd,
    0xbbbbbbbb, 0xeeeeeeee, 0xeeeeeeee, 0xffffffff
]


class CustomCipher:
    def __init__(self, key, mode=ECB, subkey_gen=True):
        self.mode = mode
        self.rounds = ROUNDS
        self.block_size = BLOCK_SIZE
        self.key = key
        self.sub_keys = [7, 7]
        # self.sub_keys = process_subkey_generation(self.key, subkey_gen)

    def round_function(self, block, i, key):
        return int(math.pow((2 * i * key), block)) % 15

    def encrypt(self, plain_text: str):
        # Initialize variables
        block_list = []
        ciphertext = ""

        # Convert each char in plaintext into ASCII, then into binary
        block_in_binary = ''.join(format(ord(char), '08b') for char in plain_text)
        print("Plaintext: " + block_in_binary)

        # If a plaintext is greater than 64 bits, then partition into sub-blocks
        if len(block_in_binary) > BLOCK_SIZE:
            print("Partition block and put in list")
            print("Get first block and process")
        else:
            padded_block = pad_block(self.block_size, block_in_binary)
            # Convert left & right half (from binary) to integers for XOR
            left_half, right_half = (int(padded_block[:(self.block_size // 2)], 2),
                                     int(padded_block[(self.block_size // 2):], 2))
            for i in range(self.rounds):
                temp = left_half
                left_half = right_half
                right_half = self.round_function(right_half, i+1, self.sub_keys[i]) ^ temp  # XOR (^)
            return (bin(left_half)[2:] + bin(right_half)[2:]).zfill(self.block_size)


# FUNC: Decrypt (ciphertext, subkey)
#   Split the block into two halves
#   Uses rounds from class attr.
#   Called using for loop based on rounds
#   RETURN: Decrypted ciphertext per round

# FUNC: Generate sub-keys (takes in an X-bit main key)
