import getopt
import sys
from utility.constants import (BLOCK_SIZE, ECB, CBC, INIT_CONFIG_ATTRIBUTES, INIT_CONFIG_TITLE,
                               INIT_CONFIG_COLUMNS)
from utility.utilities import is_valid_key, make_table


def parse_arguments():
    """
    Parse the command line for arguments.

    @return mode, subkey_gen, key:
        mode - String representing the mode of the key
        subkey_gen - Boolean representing the subkey generation decision
        key - String reresenting the key
    """
    # Initialize variables
    mode, subkey_gen_flag, key = "", "", ""
    arguments = sys.argv[1:]
    opts, _ = getopt.getopt(arguments, 'm:s:k:')

    if len(opts) == 0:
        sys.exit("[+] INIT ERROR: No arguments were provided!")

    for opt, argument in opts:
        if opt == '-m':  # For mode
            if argument.lower() in (ECB, CBC):
                mode = argument.lower()
            else:
                sys.exit("[+] INIT ERROR: An invalid mode was provided! (must choose "
                         "either ECB or CBC mode for -m option)")

        if opt == '-s':  # For subkey generation
            if argument.lower() == "true":
                subkey_gen_flag = True
            elif argument.lower() == "false":
                subkey_gen_flag = False
            else:
                sys.exit("[+] INIT ERROR: An invalid option for subkey generation was provided! (-s option)")

        if opt == '-k':  # For key
            if is_valid_key(argument, BLOCK_SIZE):
                key = argument
            else:
                sys.exit("[+] INIT ERROR: An invalid key was provided! (-k option)")

    # If no parameters provided, then resort to default
    if len(key) == 0:
        sys.exit("[+] INIT ERROR: No key was provided!")
    if len(mode) == 0:
        mode = ECB
    if isinstance(subkey_gen_flag, str):
        subkey_gen_flag = True

    return mode, subkey_gen_flag, key


def print_config(self: object):
    """
    Prints the cipher's configuration.

    @attention Use Case:
        Used only by CustomCipher class

    @param self:
        A reference to the calling class object

    @return: None
    """
    # Initialize Variables
    content = []
    attributes = vars(self)  # Get object attributes
    index = 0

    # Iterate through cipher configuration and put into a list for table
    for _, value in attributes.items():
        if index == 0:
            content.append([INIT_CONFIG_ATTRIBUTES[index], value.upper()])
        else:
            content.append([INIT_CONFIG_ATTRIBUTES[index], value])
        index += 1

    # Print config
    print("=" * 160)
    print(make_table(title=INIT_CONFIG_TITLE, columns=INIT_CONFIG_COLUMNS, content=content))
