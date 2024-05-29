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
GET_SUBKEY_USER_PROMPT = "[+] Enter 1 (to provide own sub-keys); Enter 2 (to use default sub-keys)"


# USER VIEWMODEL
MIN_MENU_ITEM_VALUE = 1
MAX_MENU_ITEM_VALUE = 8
USER_MENU_TITLE = "Menu Options"
USER_MENU_COLUMNS = ["Option", "Command"]
USER_MENU_OPTIONS_LIST = [
    ["1", "Perform Encryption"],
    ["2", "Perform Decryption"],
    ["3", "Change Mode"],
    ["4", "Change Main Key"],
    ["5", "Regenerate Sub-keys"],
    ["6", "View Cipher Settings"],
    ["7", "View Pending Operations"],
    ["8", "Close Application"],
]
USER_INPUT_PROMPT = "[+] Select a menu option: "
INVALID_MENU_SELECTION = "[+] MENU SELECTION: Please enter a valid menu option ({} to {}): "
MENU_ACTION_START_MSG = "\n[+] ACTION SELECTED: Now performing menu item {}..."
INVALID_INPUT_MENU_ERROR = "[+] ERROR: Invalid input was provided to menu: {}"
PENDING_OP_TITLE = "Pending Operations (Decryption)"
PENDING_OP_COLUMNS = ["Format", "Mode", "Encrypted Payload", "Initialization Vector (IV)"]
CACHE_FORMAT_USER_INPUT = "USER_INPUT"
CACHE_FORMAT_TEXT_FILE = "TEXT"   # => Path to file
CACHE_FORMAT_PICTURE = "PICTURE"  # => Path to file


# USER MENU - REGENERATE SUBKEYS
CHANGE_KEY_PROMPT = "[+] Please enter a new key for encryption (or enter q to exit): "
REGENERATE_SUBKEY_PROMPT = "[+] Please enter an option to generate new sub-keys: "
REGENERATE_SUBKEY_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Generate Using Main Key",
    "[+] Enter 2 - Use Default Subkeys",
    "[+] Enter 3 - Provide Own Subkeys",
]


# USER MENU - ENCRYPTION
USER_ENCRYPT_OPTIONS_PROMPT = "[+] Please select an option for encryption: "
USER_ENCRYPT_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Encrypt User Input",
    "[+] Enter 2 - Encrypt a Text File",
    "[+] Enter 3 - Encrypt a Picture (Bitmap only)",
]
USER_ENCRYPT_INPUT_PROMPT = "[+] Please enter a plaintext string to encrypt: "


# USER MENU - DECRYPTION
USER_DECRYPT_OPTIONS_PROMPT = "[+] Please select an option for decryption: "
USER_DECRYPT_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Decrypt User Input",
    "[+] Enter 2 - Decrypt a Text File",
    "[+] Enter 3 - Decrypt a Picture (Bitmap only)",
]


# OTHER CONSTANTS
OP_ENCRYPT = "ENCRYPTION"
OP_DECRYPT = "DECRYPTION"
NO_SUBKEYS_ENCRYPT_MSG = "[+] ENCRYPT ERROR: There are no sub-keys provided!"
NO_SUBKEYS_DECRYPT_MSG = "[+] DECRYPT ERROR: There are no sub-keys provided!"
