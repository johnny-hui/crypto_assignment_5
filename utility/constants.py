# CIPHER CONFIG
BLOCK_SIZE = 8  # => 8 characters or (64 bits)
ROUNDS = 8
DEFAULT_ROUND_KEYS = [
    0xdddddddd, 0xeeeeeeee, 0xaaaaaaaa, 0xdddddddd,
    0xbbbbbbbb, 0xeeeeeeee, 0xeeeeeeee, 0xffffffff
]


# CIPHER INIT
INIT_MSG = "[+] Initializing cipher..."
INIT_SUCCESS_MSG = "[+] The cipher has been successfully initialized!"

