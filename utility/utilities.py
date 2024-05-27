from utility.constants import GET_SUBKEY_USER_PROMPT


def is_valid_key(key: str, block_size: int):
    """
    Checks if the given key is of valid length
    based on block size.

    @param key:
        The key provided by the user

    @param block_size:
        The block size of the custom cipher

    @return: Boolean (T/F)
        True if valid; false otherwise
    """
    if len(key) < block_size:
        print(f"[+] INVALID KEY: An invalid key was provided (key has to be greater than {block_size} characters)")
        return False
    else:
        return True


def pad_block(block_size: int, block: str):
    """
    Pads the given block according to the block size with a
    character based on the padding length (based on the PKCS#7
    padding scheme).

    @param block_size:
        An integer representing the block size

    @param block:
        A string representing the block to be padded

    @return: padded_block
        The padded block (String)
    """
    padding_length = block_size - len(block)
    padding = chr(padding_length) * padding_length
    return block + padding


def unpad_block(block: str):
    """
    Removes padding from the given block (based on
    the PKCS#7 padding scheme).

    @param block:
        A string representing the block to be unpadded

    @return: unpadded_block
        The unpadded block (String)
    """
    padding_char = block[-1]
    return block[:-ord(padding_char)]


def encrypt_block(self: object, block: str, mode: str):
    """
    Encrypts the given block on a per round basis.

    @param self:
        A reference to the calling class object

    @param block:
        A string representing the block to be encrypted

    @param mode:
        A string representing the encryption mode

    @return: encrypted_block
        The encrypted left and right halves concatenated (string)
    """
    # Split block into two halves
    half_length = len(block) // 2
    left_half, right_half = block[:half_length], block[half_length:]

    # Apply the encryption rounds
    for subkey in self.sub_keys:
        temp = left_half
        left_half = right_half

        # XOR the result of round function and left half (converted to ASCII values)
        right_half = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(temp, self.round_function(right_half, subkey)))

    # Concatenate the two halves
    return right_half + left_half


def decrypt_block(self: object, block: str, mode: str):
    """
    Decrypts the given block on a per round basis.

    @param self:
        A reference to the calling class object

    @param block:
        A string representing the block to be encrypted

    @param mode:
        A string representing the encryption mode

    @return: decrypted_block
        The decrypted left and right halves concatenated (string)
    """
    # Split the block into two halves
    half_length = len(block) // 2
    left_half, right_half = block[:half_length], block[half_length:]

    # Apply the encryption rounds
    for subkey in reversed(self.sub_keys):
        temp = left_half
        left_half = right_half

        # XOR the result of round function and left half (converted to ASCII values)
        right_half = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(temp, self.round_function(right_half, subkey)))

    # Concatenate the two halves
    return right_half + left_half


def get_user_command_option(opt_range: tuple):
    """
    Prompts a user for a command option.

    @param opt_range:
        A tuple containing the minimum and maximum
        values for command options

    @return: command
    """
    while True:
        try:
            command = int(input(GET_SUBKEY_USER_PROMPT))
            if command in opt_range:
                break
            else:
                print("[+] ERROR: Invalid command provided; please try again.")
        except ValueError as e:
            print(f"[+] ERROR: Invalid command provided; please try again ({e})")
    return command


def get_subkeys_from_user(block_size: int, rounds: int):
    """
    Prompts the user to provide an X number of sub-keys
    based on the number of rounds.

    @param block_size:
        An integer representing the block size

    @param rounds:
        An integer representing the number of rounds

    @return: subkeys
        A list of strings containing per-round sub-keys
    """
    subkeys = []
    print(f"[+] USER-SPECIFIED KEYS: Please provide your own set of {rounds} sub-keys")

    for i in range(rounds):
        while True:
            subkey = input(f"[+] ROUND {i + 1} - Enter a key: ")
            if is_valid_key(subkey, block_size):
                subkeys.append(subkey)
                break

    return subkeys
