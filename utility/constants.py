# CIPHER CONFIG
BLOCK_SIZE = 8  # => 8 characters or (64 bits)
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


# USER PROMPTS
GET_SUBKEY_USER_PROMPT = "[+] Enter 1 (to provide own sub-keys); Enter 2 (to use default sub-keys)"
