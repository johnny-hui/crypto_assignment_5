from models.CustomCipher import CustomCipher

if __name__ == '__main__':
    cipher = CustomCipher(7)
    print(f"Ciphertext (after {cipher.rounds} rounds): " + cipher.encrypt("("))  # Equivalent '(' to 0010 1000
