import getopt
import sys

# CONSTANTS
ECB = "ecb"
CBC = "cbc"


def parse_arguments():
    """
    Parse the command line for arguments.

    @return mode, subkey_gen, key:
        Strings representing the mode and key
        A Boolean representing the subkey generation flag
    """
    # Initialize variables
    mode, subkey_gen, key = "", "", ""
    arguments = sys.argv[1:]
    opts, user_list_args = getopt.getopt(arguments, 'm:s:k')

    if len(opts) == 0:
        sys.exit("[+] INIT ERROR: No arguments were provided!")

    for opt, argument in opts:
        if opt == '-m':  # For mode
            if argument.lower() in (ECB, CBC):
                mode = argument
            else:
                sys.exit("[+] INIT ERROR: An invalid mode was provided! (must choose "
                         "either ECB or CBC mode for -m option)")

        if opt == '-s':  # For subkey generation
            if argument.lower() in ("true", "false"):
                if argument == "true":
                    subkey_gen = True
                else:
                    subkey_gen = False
            else:
                sys.exit("[+] INIT ERROR: An invalid option for subkey generation was provided! (-s option)")

        if opt == '-k':
            key = argument

    # REQUIREMENT: A main key
    if len(key) == 0:
        sys.exit("[+] INIT ERROR: No key was provided!")

    # If no parameters provided, then resort to default
    if len(mode) == 0:
        mode = ECB
    if isinstance(subkey_gen, str):
        subkey_gen = False

    return mode, subkey_gen, key

