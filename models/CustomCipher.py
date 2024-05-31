import secrets
from utility.constants import (INIT_MSG, ROUNDS, BLOCK_SIZE, DEFAULT_ROUND_KEYS,
                               OP_ENCRYPT, OP_DECRYPT, INIT_SUCCESS_MSG, GET_SUBKEY_USER_PROMPT)
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
        block_size - The block size in bytes (default=8)
        key - The main key used for encryption/decryption
        subkey_flag - A flag used to turn on subkey generation (default=True)
        iv - A randomly generated 8-byte initialization vector for CBC mode (default=None)
        sub_keys - A list containing sub-keys
        cache - A dictionary used to store the IV's for encryption/decryption in CBC mode
    """

    def __init__(self, key, mode=ECB, subkey_flag=True):
        print(INIT_MSG)
        self.mode = mode
        self.rounds = ROUNDS
        self.block_size = BLOCK_SIZE
        self.key = key
        self.subkey_flag = subkey_flag
        self.iv = None
        self.sub_keys = []
        self.process_subkey_generation()
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
            Permutates the right block by reversing the order.

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

    def encrypt(self, plaintext: str, verbose=False):
        """
        Encrypts plaintext to ciphertext using an 8-round
        Feistel architecture.

        @attention: Avalanche Analysis
            Only performable when verbose mode is on and
            is executed only in ECB mode

        @param plaintext:
            The plaintext to be encrypted (string)

        @param verbose:
            An optional boolean flag to turn on verbose mode;
            used for avalanche analysis (default=False)

        @return: ciphertext or round_data
            The encrypted plaintext (string); or if verbose mode is on
            return intermediate round_data (list[])
        """
        # Initialize Variables
        ciphertext = ''

        if is_sub_keys_generated(self.sub_keys, operation=OP_ENCRYPT) is False:
            return None

        if self.mode == ECB:
            if not verbose:  # Don't print if verbose (during avalanche analysis)
                print("[+] ECB ENCRYPTION: Now encrypting plaintext in ECB mode...")

            # Partition the plaintext into blocks and encrypt each block
            for i in range(0, len(plaintext), self.block_size):
                block = plaintext[i:i + self.block_size]

                if len(block) < self.block_size:  # Pad block to 64 bits
                    block = pad_block(self.block_size, block)

                if verbose:  # For avalanche analysis (1 block only)
                    round_data = encrypt_block(self, block, verbose=True)
                    round_data.append(self.key)
                    return round_data

                ciphertext += encrypt_block(self, block)

        if self.mode == CBC:
            print("[+] CBC ENCRYPTION: Now encrypting plaintext in CBC mode...")

            self.iv = secrets.token_bytes(self.block_size)  # Generate IV of block size
            previous_block = self.iv.decode('latin-1')  # Use 'latin-1' encoding (ensures each char is a value 0-255)

            for i in range(0, len(plaintext), self.block_size):
                block = plaintext[i:i + self.block_size]

                if len(block) < self.block_size:
                    block = pad_block(self.block_size, block)

                block = ''.join(chr(ord(p) ^ ord(c)) for p, c in zip(previous_block, block))  # XOR with previous block
                encrypted_block = encrypt_block(self, block)
                ciphertext += encrypted_block
                previous_block = encrypted_block

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
            print("[+] CBC DECRYPTION: Now decrypting ciphertext in CBC mode...")

            # Get IV from class
            previous_block = self.iv.decode('latin-1')

            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                decrypted_block = decrypt_block(self, block)
                plaintext_block = ''.join(chr(ord(p) ^ ord(c)) for p, c in zip(previous_block, decrypted_block))
                plaintext += plaintext_block
                previous_block = block

            self.iv = None  # Reset IV for next encryption

        if len(plaintext) % self.block_size == 0:
            plaintext = unpad_block(plaintext)

        return plaintext

    def process_subkey_generation(self, menu_option=None):
        """
        Generates sub-keys from a main key if the subkey_flag
        is set to True; otherwise, prompts the user to use default
        sub-keys or provide their own sub-keys.

        @param menu_option:
            An optional parameter used when function
            is called by UserMenu class (default=None)

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

        # a) Check if call is from UserMenu (to regenerate sub-keys)
        if menu_option is not None:
            self.sub_keys.clear()  # Clear existing sub-keys
            if menu_option == 1:
                generate_subkeys()
            if menu_option == 2:
                self.sub_keys = get_default_subkeys(DEFAULT_ROUND_KEYS)
            if menu_option == 3:
                self.sub_keys = get_subkeys_from_user(self.block_size, self.rounds)

        # b) Otherwise generate sub-keys based on subkey_flag
        else:
            if self.subkey_flag:
                generate_subkeys()
            else:
                command = get_user_command_option(opt_range=(1, 2), msg=GET_SUBKEY_USER_PROMPT)
                if command == 1:
                    self.sub_keys = get_subkeys_from_user(self.block_size, self.rounds)
                if command == 2:
                    self.sub_keys = get_default_subkeys(DEFAULT_ROUND_KEYS)

        print(f"[+] OPERATION SUCCESSFUL: {self.rounds} new sub-keys have been added!")
