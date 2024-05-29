# CIPHER CONFIG
BLOCK_SIZE = 8  # => 8 char(bytes) or (64 bits)
ROUNDS = 8
DEFAULT_ROUND_KEYS = [
    0xdddddddd, 0xeeeeeeee, 0xaaaaaaaa, 0xdddddddd,
    0xbbbbbbbb, 0xeeeeeeee, 0xeeeeeeee, 0xffffffff
]
ECB = "ecb"
CBC = "cbc"


# CIPHER INIT
INIT_MSG = "[+] Initializing cipher..."
INIT_SUCCESS_MSG = "[+] The cipher has been successfully initialized!"
INIT_CONFIG_TITLE = "Cipher Settings"
INIT_CONFIG_COLUMNS = ["Setting", "Value"]
INIT_CONFIG_ATTRIBUTES = [
    "Mode", "Number of Rounds", "Block Size (bytes)", "Main Key",
    "Subkey Generation", "Initialization Vector(IV)", "Sub-keys"
]


# USER MENU
MIN_MENU_ITEM_VALUE = 1
MAX_MENU_ITEM_VALUE = 7
USER_MENU_TITLE = "Menu Options"
USER_MENU_COLUMNS = ["Option", "Command"]
USER_MENU_OPTIONS_LIST = [
    ["1", "Perform Encryption"],  # TODO: Provide options to encrypt what (textfile, string input, picture)
    ["2", "Perform Decryption"],  # TODO: Provide options to decrypt what (textfile, string input, picture)
    ["3", "Change Mode"],
    ["4", "Change Main Key"],
    ["5", "Regenerate Sub-keys"],
    ["6", "View Cipher Settings"],
    ["7", "Close Application"],
]
USER_INPUT_PROMPT = "[+] Select a menu option: "
INVALID_MENU_SELECTION = "[+] MENU SELECTION: Please enter a valid menu option ({} to {}): "
MENU_ACTION_START_MSG = "\n[+] ACTION SELECTED: Now performing menu item {}..."
INVALID_INPUT_MENU_ERROR = "[+] ERROR: Invalid input was provided to menu: {}"
CHANGE_KEY_PROMPT = "[+] Please enter a new key for encryption (or enter q to exit): "
REGENERATE_SUBKEY_PROMPT = ("[+] Please enter an option to generate new sub-keys: (Enter 1 to generate using main key);"
                            " (Enter 2 to use default sub-keys); (Enter 3 to use own sub-keys); (or enter 0 to exit): ")


# USER PROMPTS
GET_SUBKEY_USER_PROMPT = "[+] Enter 1 (to provide own sub-keys); Enter 2 (to use default sub-keys)"


# OTHER CONSTANTS
OP_ENCRYPT = "ENCRYPTION"
OP_DECRYPT = "DECRYPTION"
NO_SUBKEYS_ENCRYPT_MSG = "[+] ENCRYPT ERROR: There are no sub-keys provided!"
NO_SUBKEYS_DECRYPT_MSG = "[+] DECRYPT ERROR: There are no sub-keys provided!"
