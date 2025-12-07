# AES Encryption and Decryption using PyCryptodome (CBC Mode)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_aes(plaintext, key_text):
    # Convert key to bytes and make sure it's 16 bytes (AES-128)
    key = key_text.encode('utf-8')
    key = key[:16].ljust(16, b'\0')   # trim or pad with null bytes

    # Generate random IV (initialization vector)
    iv = get_random_bytes(16)

    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad plaintext to block size (16 bytes) and encrypt
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return iv, ciphertext


def decrypt_aes(iv, ciphertext, key_text):
    # Convert key to bytes and make sure it's 16 bytes
    key = key_text.encode('utf-8')
    key = key[:16].ljust(16, b'\0')

    # Create AES cipher with same key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and unpad
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')


def main():
    print("=== AES-128 Encryption/Decryption (CBC Mode) ===\n")

    plaintext = input("Enter plaintext: ")
    key_text  = input("Enter key (max 16 characters): ")

    # Encrypt
    iv, ciphertext = encrypt_aes(plaintext, key_text)
    print("\n--- Encryption ---")
    print("IV (hex)         :", iv.hex())
    print("Ciphertext (hex) :", ciphertext.hex())

    # Decrypt
    decrypted = decrypt_aes(iv, ciphertext, key_text)
    print("\n--- Decryption ---")
    print("Decrypted text   :", decrypted)


if __name__ == "__main__":
    main()
