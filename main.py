from models.CustomCipher import CustomCipher
from utility.init import parse_arguments

if __name__ == '__main__':
    mode, subkey_flag, key = parse_arguments()
    cipher = CustomCipher(key, mode, subkey_flag)
    ciphertext = cipher.encrypt("Booba")
    print(f"[+] Ciphertext (after {cipher.rounds} rounds): " + ciphertext)

    plaintext = cipher.decrypt(ciphertext)
    print(f"[+] Plaintext (after {cipher.rounds} rounds): " + plaintext)
