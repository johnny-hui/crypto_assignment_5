# CIPHER CONFIG
BLOCK_SIZE = 8  # => 8 characters or (64 bits)
ROUNDS = 8
DEFAULT_ROUND_KEYS = [
    0xdddddddd, 0xeeeeeeee, 0xaaaaaaaa, 0xdddddddd,
    0xbbbbbbbb, 0xeeeeeeee, 0xeeeeeeee, 0xffffffff
]
ECB = "ecb"
CBC = "cbc"


# USER MENU


# CIPHER INIT
INIT_MSG = "[+] Initializing cipher..."
INIT_SUCCESS_MSG = "[+] The cipher has been successfully initialized!"


# USER PROMPTS
GET_SUBKEY_USER_PROMPT = "[+] Enter 1 (to provide own sub-keys); Enter 2 (to use default sub-keys)"

# OTHER CONSTANTS
OP_ENCRYPT = "ENCRYPTION"
OP_DECRYPT = "DECRYPTION"
NO_SUBKEYS_ENCRYPT_MSG = "[+] ENCRYPT ERROR: There are no sub-keys provided!"
NO_SUBKEYS_DECRYPT_MSG = "[+] DECRYPT ERROR: There are no sub-keys provided!"
