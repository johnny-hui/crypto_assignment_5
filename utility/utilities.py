from typing import TextIO
from prettytable import PrettyTable
from utility.constants import GET_SUBKEY_USER_PROMPT, OP_DECRYPT, OP_ENCRYPT, NO_SUBKEYS_ENCRYPT_MSG, \
    NO_SUBKEYS_DECRYPT_MSG, INVALID_MENU_SELECTION, MENU_ACTION_START_MSG, INVALID_INPUT_MENU_ERROR, ECB, CBC, \
    CHANGE_KEY_PROMPT, REGENERATE_SUBKEY_PROMPT, REGENERATE_SUBKEY_OPTIONS, USER_ENCRYPT_OPTIONS_PROMPT, \
    USER_ENCRYPT_OPTIONS, USER_ENCRYPT_INPUT_PROMPT, CACHE_FORMAT_USER_INPUT, PENDING_OP_TITLE, PENDING_OP_COLUMNS


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
        print(f"[+] INVALID KEY: An invalid key was provided (key has to be greater than {block_size} characters)!")
        return False
    else:
        return True


def is_sub_keys_generated(subkeys: list, operation: str):
    """
    Checks if sub-keys are generated; this function is
    called before encryption or decryption is performed.

    @param subkeys:
        A list containing sub-keys from the calling class

    @param operation:
        A string denoting the operation to be performed

    @return: Boolean (T/F)
        True if sub-keys are generated; false otherwise
    """
    if operation == OP_ENCRYPT:
        if len(subkeys) == 0:
            print(NO_SUBKEYS_ENCRYPT_MSG)
            return False
    if operation == OP_DECRYPT:
        if len(subkeys) == 0:
            print(NO_SUBKEYS_DECRYPT_MSG)
            return False
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
    Removes padding from any given block (based on
    the PKCS#7 padding scheme).

    @param block:
        A string representing the block to be unpadded

    @return: unpadded_block
        The unpadded block (String)
    """
    padding_char = block[-1]
    padding_len = ord(padding_char)
    if block.endswith(padding_char * padding_len):
        return block[:-padding_len]
    return block


def encrypt_block(self: object, block: str):
    """
    Encrypts the given block on a per round basis.

    @param self:
        A reference to the calling class object

    @param block:
        A string representing the block to be encrypted

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


def decrypt_block(self: object, block: str):
    """
    Decrypts the given block on a per round basis.

    @param self:
        A reference to the calling class object

    @param block:
        A string representing the block to be encrypted

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


def get_default_subkeys(default_keys: list[int]):
    """
    Fetches default sub-keys (in hex), converts them
    to strings and puts them into a list.

    @param default_keys:
        A list of default sub-keys (in hex)

    @return: sub_keys
        A list containing the default sub-keys (strings)
    """
    sub_keys = []
    print(f"[+] DEFAULT SUBKEYS: Fetching default subkeys...")
    for round, key in enumerate(default_keys):
        round += 1
        subkey = hex(key)[2:].zfill(8)
        sub_keys.append(subkey)
        print(f"[+] ROUND {round}: {subkey}")
    return sub_keys


def make_table(title: str, columns: list[str], content: list[list[str]]):
    """
    Constructs a PrettyTable.

    @param title:
        A string containing the title of the table

    @param columns:
        A list of strings containing the columns(fields) of the table

    @param content:
        A list containing the contents of the table

    @return: table
        A PrettyTable object.
    """
    table = PrettyTable()
    table.title = title
    table.field_names = columns
    for item in content:
        table.add_row(item)
    return table


# USER MENU FUNCTIONS
def get_user_menu_option(fd: TextIO, min_num_options: int, max_num_options: int):
    """
    Gets the user selection for the menu.

    @param fd:
        The file descriptor for stdin

    @param min_num_options:
        The minimum number of options possible

    @param max_num_options:
        The maximum number of options possible

    @return: command
        An integer representing the selection
    """
    while True:
        try:
            command = int(fd.readline().strip())
            while not (min_num_options <= command <= max_num_options):
                print(INVALID_MENU_SELECTION.format(min_num_options, max_num_options))
                command = int(fd.readline().strip())
            print(MENU_ACTION_START_MSG.format(command))
            return command
        except (ValueError, TypeError) as e:
            print(INVALID_INPUT_MENU_ERROR.format(e))
            print(INVALID_MENU_SELECTION.format(min_num_options, max_num_options))


def change_mode(cipher: object):
    """
    Toggles a change to the CustomCipher's mode.

    @attention: Use Case
        This function is called by UserViewModel class

    @param cipher:
        A CustomCipher object

    @return: None
    """
    if cipher.mode == ECB:
        cipher.mode = CBC
    else:
        cipher.mode = ECB
    print(f"[+] MODE CHANGED TO -> {cipher.mode.upper()}")


def change_main_key(cipher: object):
    """
    Prompts the user for a new main key for
    the CustomCipher and replaces the old key.

    @attention: Use Case
        This function is called by UserViewModel class

    @param cipher:
        A CustomCipher object

    @return: None
    """
    while True:
        key = input(CHANGE_KEY_PROMPT)
        if key == 'q':
            return None
        if is_valid_key(key, cipher.block_size):
            cipher.key = key
            print(f"[+] KEY CHANGED: The main key has been changed to -> '{key}'")
            print("[+] HINT: To generate sub-keys with this new main key, perform the "
                  "'Regenerate Sub-keys' command in menu")
            return None


def regenerate_sub_keys(cipher: object):
    """
    Regenerates sub-keys by using either the main key,
    default sub-keys, or user-provided sub-keys.

    @attention: Use Case
        This function is called by UserViewModel class

    @param cipher:
        A CustomCipher object

    @return: None
    """
    for item in REGENERATE_SUBKEY_OPTIONS:
        print(item)

    while True:
        try:
            option = int(input(REGENERATE_SUBKEY_PROMPT))
            if option == 0:
                return None
            elif option in (1, 2, 3):
                cipher.process_subkey_generation(menu_option=option)
                return None
            else:
                print("[+] Invalid option selected; please try again!")
        except (ValueError, TypeError) as e:
            print(f"[+] Invalid option selected; please try again! ({e})")


def view_pending_operations(self: object):
    """
    Prints the pending decryption operations that
    are available to the user.

    @attention Use Case:
        This function is only called by the UserViewModel class

    @attention Removal of Bytes in Ciphertext
        This does not affect the original ciphertext saved, as this is
        performed to make the ciphertext more presentable to the user.

    @param self:
        A reference to the calling class object (UserViewModel)

    @return: None
    """
    if len(self.pending_operations) == 0:
        print("[+] VIEW PENDING OPERATIONS: There are currently no pending operations!")
        return None
    else:
        content_list = []
        for key, (mode, ciphertext, iv) in self.pending_operations.items():
            ciphertext = ''.join(char for char in ciphertext if char.isprintable())  # Remove bytes from ciphertext
            content_list.append([key, mode, ciphertext, iv])
        print(make_table(title=PENDING_OP_TITLE, columns=PENDING_OP_COLUMNS, content=content_list))


def encrypt(self: object, cipher: object):
    """
    Prompts the user on the type of encryption
    (user input, text file, or picture) and invokes
    on the cipher object to perform the encryption.

    @attention Use Case:
        This function is only called by the UserViewModel class

    @param self:
        A reference to the calling class object (UserViewModel)

    @param cipher:
        A CustomCipher object

    @return: encrypted_object
        The encrypted object (user input, text file, or picture)
    """
    for item in USER_ENCRYPT_OPTIONS:
        print(item)

    while True:
        try:
            option = int(input(USER_ENCRYPT_OPTIONS_PROMPT))

            if option == 0:  # Quit
                return None

            if option == 1:  # For User Input (from stdin)
                user_text = input(USER_ENCRYPT_INPUT_PROMPT)
                ciphertext = cipher.encrypt(user_text)
                if cipher.mode == ECB:
                    self.pending_operations[CACHE_FORMAT_USER_INPUT] = (cipher.mode.upper(), ciphertext, None)
                else:
                    self.pending_operations[CACHE_FORMAT_USER_INPUT] = (cipher.mode.upper(), ciphertext, cipher.iv)
                print(f"[+] OPERATION COMPLETED: The corresponding ciphertext -> {ciphertext}")
                return None

            if option == 2:  # For Text File
                print("PLACEHOLDER")
                return None

            if option == 3:  # For Picture (Bitmap)
                print("PLACEHOLDER")
                return None

            print("[+] Invalid option selected; please try again!")
        except (ValueError, TypeError) as e:
            print(f"[+] Invalid option selected; please try again! ({e})")


def decrypt(self: object, cipher: object):
    """
    Prompts the user on the type of decryption
    (user input, text file, or picture) and invokes
    on the cipher object to perform the decryption.

    @attention Use Case:
        This function is only called by the UserViewModel class

    @param self:
        A reference to the calling class object (UserViewModel)

    @param cipher:
        A CustomCipher object

    @return: decrypted_object
        The decrypted object (user input, text file, or picture)
    """
    print("PLACEHOLDER")
