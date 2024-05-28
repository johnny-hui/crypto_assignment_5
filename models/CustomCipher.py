import base64
import secrets
from utility.constants import (INIT_MSG, INIT_SUCCESS_MSG, ROUNDS,
                               BLOCK_SIZE, DEFAULT_ROUND_KEYS, OP_ENCRYPT, OP_DECRYPT)
from utility.init import ECB, CBC
from utility.utilities import (pad_block, encrypt_block, decrypt_block,
                               unpad_block, get_subkeys_from_user, get_user_command_option, get_default_subkeys,
                               is_sub_keys_generated)


class CustomCipher:
    """ A class representing the custom Feistel cipher.

    @attention: CBC Encryption Mode
        This cipher also supports CBC encryption (use '-m CBC' as program argument)

    Attributes:
        mode - The encryption mode of the cipher (default=ECB)
        rounds - The number of rounds the cipher should run (default=8)
        block_size - The block size in bits (default=64)
        key - The main key used for encryption/decryption
        subkey_flag - A flag used to turn on subkey generation (default=True)
        sub_keys - A list containing sub-keys
    """
    def __init__(self, key, mode=ECB, subkey_flag=True):
        print(INIT_MSG)
        self.mode = mode  # Print config upon init
        self.rounds = ROUNDS  # Print config upon init
        self.block_size = BLOCK_SIZE  # Print config upon init
        self.key = key  # Print config upon init
        self.iv = None  # Print config upon init
        self.subkey_flag = subkey_flag  # Print config upon init (TODO: can be altered in menu)
        self.sub_keys = []
        self.__process_subkey_generation()
        print(INIT_SUCCESS_MSG)

    def round_function(self, right_block: str, key: str):
        """
        A basic round function that involves substitution
        and permutation of the right block, followed by an
        XOR operation with the key.

        @param right_block:
            A string containing the right block

        @param key:
            A string representing the subkey

        @return: result
            A string representing the transformed right block
        """
        def substitute(byte: str):
            """
            Substitution of a character(byte) of the right block
            by taking ASCII value modulo 256.

            @param byte:
                A string containing a single character (8-bits)

            @return: chr(ord(byte) % 256)
                The substituted character
            """
            return chr(ord(byte) % 256)

        def permutation(block: str):
            """
            Permutate the right block by reversing the order.

            @param block:
                A string containing characters (bytes) of
                the right block

            @return: block[::-1]
                The reversed order of the right block
            """
            return block[::-1]

        # SUBSTITUTION: Each byte(char) of right block
        new_right_block = ''.join(substitute(byte) for byte in right_block)

        # PERMUTATION: Reverses the order of bytes(char)
        new_right_block = permutation(new_right_block)

        # XOR with the subkey
        return ''.join(chr(ord(r) ^ ord(k)) for r, k in zip(new_right_block, key))

    def encrypt(self, plaintext: str):
        """
        Encrypts plaintext to ciphertext using an 8-round
        Feistel architecture.

        @param plaintext:
            The plaintext to be encrypted (string)

        @return: ciphertext
            The encrypted plaintext (string)
        """
        # Initialize Variables
        ciphertext = ''

        if is_sub_keys_generated(self.sub_keys, operation=OP_ENCRYPT) is False:
            return None

        if self.mode == ECB:
            print("[+] ECB ENCRYPTION: Now encrypting plaintext in ECB mode...")

            # Partition the plaintext into blocks and encrypt each block
            for i in range(0, len(plaintext), self.block_size):
                block = plaintext[i:i + self.block_size]

                if len(block) < self.block_size:  # Pad block to 64
                    block = pad_block(self.block_size, block)

                ciphertext += encrypt_block(self, block)

        if self.mode == CBC:
            print("[+] CBC ENCRYPTION: Now encrypting plaintext in CBC mode...")

            # Generate a random initialization vector (IV)
            self.iv = base64.b64encode(secrets.token_bytes(self.block_size)).decode()
            previous_block = self.iv

            # Partition the plaintext into blocks and encrypt each block
            for i in range(0, len(plaintext), self.block_size):
                block = plaintext[i:i + self.block_size]

                if len(block) < self.block_size:  # Pad block to 64
                    block = pad_block(self.block_size, block)

                # XOR with the previous ciphertext block
                block = ''.join(chr(ord(p) ^ ord(c)) for p, c in zip(previous_block, block))

                # Encrypt the block
                ciphertext += encrypt_block(self, block)

                # Set previous block to new ciphertext block
                previous_block = ciphertext

        return ciphertext

    def decrypt(self, ciphertext: str):
        """
        Decrypts ciphertext back into plaintext using an 8-round
        Feistel architecture.

        @param ciphertext:
            The ciphertext to be decrypted (string)

        @return: plaintext
            The decrypted plaintext (string)
        """
        # Initialize Variables
        plaintext = ''

        if is_sub_keys_generated(self.sub_keys, operation=OP_DECRYPT) is False:
            return None

        if self.mode == ECB:
            print("[+] ECB DECRYPTION: Now decrypting plaintext in ECB mode...")

            # Partition the ciphertext into blocks and decrypt each block
            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                plaintext_block = decrypt_block(self, block)
                plaintext += plaintext_block

        if self.mode == CBC:
            print("[+] CBC DECRYPTION: Now decrypting plaintext in CBC mode...")
            previous_block = self.iv

            # Partition the ciphertext into blocks and decrypt each block
            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                decrypted_block = decrypt_block(self, block)

                # XOR with previous block
                plaintext_block = ''.join(chr(ord(p) ^ ord(c)) for p, c in zip(previous_block, decrypted_block))
                plaintext += plaintext_block
                previous_block = block

            # Reset IV for next encryption
            self.iv = None

        if len(plaintext) % self.block_size == 0:
            plaintext = unpad_block(plaintext)

        return plaintext

    def __process_subkey_generation(self):
        """
        A helper function that generates sub-keys from a main key
        if the subkey_flag is set to True; otherwise, prompts the
        user to use default sub-keys or provides own sub-keys.

        @return: None
        """
        def generate_subkeys():
            """
            Generates a set of sub-keys from the main key on a
            per-round basis based on a permutation scheme.

            @attention: Permutation Scheme
                - a) Perform byte rotation with round number and length of the key
                - b) XOR each byte of the shifted result with the round number

            @return: None
            """
            print(f"[+] Generating sub-keys from the following main key: {self.key}")

            # Ensure the main key is of sufficient size
            if len(self.key) < self.block_size:
                self.key = (self.key * (self.block_size // len(self.key) + 1))[:self.block_size]

            # Convert each character of key to ASCII values
            key_bytes = [ord(char) for char in self.key]

            # Round-key generation with a permutation scheme
            for i in range(self.rounds):
                # a) Byte rotation with round number and length of the key
                subkey = key_bytes[i % len(self.key):] + key_bytes[:i % len(self.key)]

                # b) XOR each byte of the shifted result with the round number
                subkey = [(byte ^ (i + 1)) for byte in subkey]
                self.sub_keys.append(''.join(chr(byte) for byte in subkey))
        print("[+] SUBKEY GENERATION: Now processing sub-keys...")

        if self.subkey_flag:
            generate_subkeys()
        else:
            command = get_user_command_option(opt_range=(1, 2))
            if command == 1:
                self.sub_keys = get_subkeys_from_user(self.block_size, self.rounds)
            if command == 2:
                self.sub_keys = get_default_subkeys(DEFAULT_ROUND_KEYS)

        print(f"[+] OPERATION SUCCESSFUL: {self.rounds} sub-keys have been added!")
