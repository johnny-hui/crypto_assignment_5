def is_valid_key(key):
    """
    Checks if the given key is of valid format.

    @param key:
        The key provided by the user

    @return: Boolean (T/F)
        True if valid; false otherwise
    """
    # Check if the key is in hexadecimal format
    if not all(c in '0123456789abcdefABCDEF' for c in key):
        return False

    # Check if the length of the key is appropriate (e.g., 128 bits)
    if len(key) != 32:
        return False

    return True


def process_subkey_generation(key, subkey_gen_flag: bool):
    """
    An initialization function that generates sub-keys
    per round if subkey_gen_flag is True.

    @param key:
        The key provided by the user

    @param subkey_gen_flag:
        A boolean indicating whether sub-keys should be generated

    @return: list
        A list of sub-keys per round
    """
    if subkey_gen_flag:
        print("Call function to generate sub-keys based on the main key")
    else:
        print("Prompt user if they want to use default round keys or user-specified keys per round")
    return []


def pad_block(block_size: int, block: str):
    """
    Pads the given block with leading zeroes,
    based on the block size in bits.

    @param block_size:
        An integer representing the block size

    @param block:
        A string representing the block to be padded

    @return: padded_block
        The padded block (String)
    """
    padded_block = block.zfill(block_size)
    return padded_block
