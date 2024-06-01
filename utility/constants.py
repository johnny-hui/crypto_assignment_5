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
MAX_MENU_ITEM_VALUE = 9
USER_MENU_TITLE = "Menu Options"
USER_MENU_COLUMNS = ["Option", "Command"]
USER_MENU_OPTIONS_LIST = [
    ["1", "Perform Encryption"],
    ["2", "Perform Decryption"],
    ["3", "Perform Avalanche Analysis"],
    ["4", "Change Mode"],
    ["5", "Change Main Key"],
    ["6", "Regenerate Sub-keys"],
    ["7", "View Cipher Settings"],
    ["8", "View Pending Operations"],
    ["9", "Close Application"],
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
USER_ENCRYPT_FILE_PATH_PROMPT = "[+] Please enter the path of the text file to encrypt: "
USER_ENCRYPT_IMAGE_PATH_PROMPT = "[+] Please enter the path of the image file to encrypt: "


# USER MENU - DECRYPTION
USER_DECRYPT_OPTIONS_PROMPT = "[+] Please select an option for decryption: "
USER_DECRYPT_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Decrypt User Input",
    "[+] Enter 2 - Decrypt a Text File",
    "[+] Enter 3 - Decrypt a Picture (Bitmap only)"
]


# AVALANCHE ANALYSIS
AVALANCHE_ANALYSIS_SPAC_PROMPT = ("[+] AVALANCHE ANALYSIS: Enter 1 to provide own plaintext message (64-bit or 8 char "
                                  "only; Enter 2 to use generated plaintext message; or (Enter 0 to quit): ")
AVALANCHE_ANALYSIS_SKAC_PROMPT = ("[+] AVALANCHE ANALYSIS: Enter 1 to provide own key (64-bit or 8 char) "
                                  "only; Enter 2 to use a randomly generated a key; or (Enter 0 to quit): ")
AVALANCHE_ANALYSIS_USER_INPUT_KEY = "[+] Enter a key (8 characters only): "
AVALANCHE_ANALYSIS_USER_INPUT = "[+] Enter a plaintext message (8 characters only): "
AVALANCHE_TASK_SPAC_TITLE = "Encryption {} Bit Change in Plaintext (SPAC) - [Starting from MSB]"
AVALANCHE_TASK_SKAC_TITLE = ("Encrypting Ciphertext after {} Bit Changes in Key (SKAC) - {} 4th Bit Position "
                             "[Starting from MSB]")


# OTHER CONSTANTS
OP_ENCRYPT = "ENCRYPTION"
OP_DECRYPT = "DECRYPTION"
NO_SUBKEYS_ENCRYPT_MSG = "[+] ENCRYPT ERROR: There are no sub-keys provided!"
NO_SUBKEYS_DECRYPT_MSG = "[+] DECRYPT ERROR: There are no sub-keys provided!"
GRAPH_LABEL_SPAC = ["1 Bit Change in Plaintext", "2 Bit Change in Plaintext", "3 Bit Change in Plaintext",
                    "4 Bit Change in Plaintext", "5 Bit Change in Plaintext", "6 Bit Change in Plaintext",
                    "7 Bit Change in Plaintext", "8 Bit Change in Plaintext", "9 Bit Change in Plaintext",
                    "10 Bit Change in Plaintext"]
GRAPH_LABEL_SKAC = ["1 Bit Change in Key", "2 Bit Change in Key", "3 Bit Change in Key",
                    "4 Bit Change in Key", "5 Bit Change in Key", "6 Bit Change in Key",
                    "7 Bit Change in Key", "8 Bit Change in Key", "9 Bit Change in Key",
                    "10 Bit Change in Key"]
SAVE_GRAPH_DIR = "data/graphs/{}"
