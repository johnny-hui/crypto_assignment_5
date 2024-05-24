BLOCK_SIZE = 64
ROUNDS = 8
DEFAULT_ROUND_KEYS = [
    0xdddddddd, 0xeeeeeeee, 0xaaaaaaaa, 0xdddddddd,
    0xbbbbbbbb, 0xeeeeeeee, 0xeeeeeeee, 0xffffffff
]

class Cipher(object):

# CLASS: Cipher(key, mode=ECB, subkey_gen=True)
#   Set as class attributes

# FUNC: Round Function (block, key)
#   RETURN: The result

# FUNC: Encrypt (plaintext, subkey)
#   Split the block into two halves
#   Uses rounds from class attr.
#   Called using for loop based on rounds
#   TECHNIQUE: Recursion
#   RETURN: Ciphertext per round

# FUNC: Decrypt (ciphertext, subkey)
#   Uses rounds from class attr.
#   Called using for loop based on rounds
#   TECHNIQUE: Recursion
#   RETURN: Decrypted ciphertext per round

# FUNC: Generate sub-keys (takes in an X-bit main key)
