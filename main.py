from models.CustomCipher import CustomCipher

if __name__ == '__main__':
    cipher = CustomCipher('secretkey', subkey_flag=False)
    ciphertext = cipher.encrypt("Hello World")
    print(f"[+] Ciphertext (after {cipher.rounds} rounds): " + ciphertext)

    plaintext = cipher.decrypt(ciphertext)
    print(f"[+] Plaintext (after {cipher.rounds} rounds): " + plaintext)
