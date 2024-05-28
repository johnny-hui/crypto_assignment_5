from models.CustomCipher import CustomCipher

if __name__ == '__main__':
    cipher = CustomCipher('mysecretkey')
    ciphertext = cipher.encrypt("12345678")
    print(f"[+] Ciphertext (after {cipher.rounds} rounds): " + ciphertext)

    plaintext = cipher.decrypt(ciphertext)
    print(f"[+] Plaintext (after {cipher.rounds} rounds): " + plaintext)
