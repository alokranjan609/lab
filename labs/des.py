# DES Encryption and Decryption using PyCryptodome (ECB Mode)

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def main():
    print("=== DES Encryption and Decryption (ECB Mode) ===\n")

    # Take plaintext and key from user
    plaintext = input("Enter plaintext: ")
    key_text = input("Enter key (exactly 8 characters): ")

    # Ensure key is 8 bytes (DES uses 64-bit key)
    key = key_text.encode('utf-8')
    if len(key) < 8:
        # pad key if too short
        key = key.ljust(8, b'0')
    elif len(key) > 8:
        # truncate if too long
        key = key[:8]

    # Create DES cipher in ECB mode
    cipher = DES.new(key, DES.MODE_ECB)

    # Convert plaintext to bytes and pad to 8-byte blocks
    plaintext_bytes = plaintext.encode('utf-8')
    padded_plaintext = pad(plaintext_bytes, DES.block_size)  # block_size = 8

    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)

    print("\n--- Encryption ---")
    print("Key (hex)        :", key.hex())
    print("Plaintext (hex)  :", plaintext_bytes.hex())
    print("Padded text (hex):", padded_plaintext.hex())
    print("Ciphertext (hex) :", ciphertext.hex())

    # Decrypt
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, DES.block_size)
    decrypted_text = decrypted.decode('utf-8')

    print("\n--- Decryption ---")
    print("Decrypted (hex)  :", decrypted.hex())
    print("Decrypted text   :", decrypted_text)

if __name__ == "__main__":
    main()
