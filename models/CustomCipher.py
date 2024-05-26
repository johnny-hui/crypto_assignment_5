from utility.constants import INIT_MSG, INIT_SUCCESS_MSG, ROUNDS, BLOCK_SIZE, DEFAULT_ROUND_KEYS
from utility.init import ECB
from utility.utilities import pad_block, encrypt_block, decrypt_block, unpad_block, is_valid_key


class CustomCipher:
    """ A class representing the custom Feistel cipher.

    @attention: CBC Encryption Mode Supported
        This cipher also supports CBC encryption (use '-m CBC' as program argument)

    Attributes:
        mode - The encryption mode of the cipher (default=ECB)
        rounds - The number of rounds the cipher should run (default=8)
        block_size - The block size in bits (default=64)
        key - The main key used for encryption/decryption
        subkey_flag - A flag used to turn on subkey generation
        sub_keys - A list containing sub-keys
    """
    def __init__(self, key, mode=ECB, subkey_flag=True):
        print(INIT_MSG)
        self.mode = mode  # Print config upon init
        self.rounds = ROUNDS  # Print config upon init
        self.block_size = BLOCK_SIZE  # Print config upon init
        self.key = key  # Print config upon init
        self.subkey_flag = subkey_flag  # Print config upon init (TODO: can be altered in menu)
        self.sub_keys = []
        self.__process_subkey_generation()
        print(INIT_SUCCESS_MSG)

    def round_function(self, right_block: str, key: str):
        """
        A basic round function for the custom Feistel cipher
        that involves XOR'ing the right block with the key.

        @param right_block:
            A string containing the right block

        @param key:
            A string representing the key

        @return: XOR'd result
            The result of XOR'ing right block and key
        """
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(right_block, key))

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

        if len(self.sub_keys) == 0:
            print("[+] ENCRYPT ERROR: There are no sub-keys provided!")
            return None

        if self.mode == ECB:
            print("[+] ENCRYPTION: Now encrypting plaintext in ECB mode...")

            # Partition the plaintext into blocks and encrypt each block
            for i in range(0, len(plaintext), self.block_size):
                block = plaintext[i:i + self.block_size]

                if len(block) < self.block_size:  # Pad block to 64
                    block = pad_block(self.block_size, block)

                ciphertext += encrypt_block(self, block, self.mode)

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

        if len(self.sub_keys) == 0:
            print("[+] ENCRYPT ERROR: There are no sub-keys provided!")
            return None

        if self.mode == ECB:
            print("[+] Now encrypting plaintext in ECB mode...")

            # Partition the ciphertext into blocks and decrypt each block
            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                plaintext += decrypt_block(self, block, self.mode)

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
        command = None
        print("[+] SUBKEY GENERATION: Now processing sub-keys...")

        # If subkey generation is enabled
        if self.subkey_flag is True:
            print(f"[+] Generating sub-keys from the following main key: {self.key}")
            for i in range(self.rounds):
                subkey = self.key[i % len(self.key):] + self.key[:i % len(self.key)]
                self.sub_keys.append(subkey)
        else:
            try:
                while command not in (1, 2):
                    command = int(input("[+] Enter 1 (to provide own sub-keys); Enter 2 (to use default sub-keys)"))

                # TODO: Refactor into separate functions for each command
                if command == 1:
                    print(f"[+] USER-SPECIFIED KEYS: Please provide your own set of {self.rounds} sub-keys")
                    for i in range(self.rounds):
                        while True:
                            subkey = input(f"[+] ROUND {i + 1} - Enter a key: ")
                            if is_valid_key(subkey, self.block_size):
                                self.sub_keys.append(subkey)
                                break
                if command == 2:
                    for key in DEFAULT_ROUND_KEYS:
                        self.sub_keys.append(hex(key)[2:].zfill(8))
            except ValueError as e:
                print(f"[+] ERROR: Invalid command provided; please try again. ({e})")

        print(f"[+] OPERATION SUCCESSFUL: {self.rounds} sub-keys have been added!")
