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
    Pads the given block with leading zeroes, based on
    the block size in bits.

    @param block_size:
        An integer representing the block size

    @param block:
        A string representing the block to be padded

    @return: padded_block
        The padded block (String)
    """
    return block + (chr(block_size - len(block)) * (block_size - len(block)))


def unpad_block(block: str):
    """
    Removes padding from the given block.

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
