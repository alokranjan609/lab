# Program to break a Shift (Caesar) Cipher by brute force

def decrypt_with_key(ciphertext, key):
    result = ""

    for ch in ciphertext:
        if 'A' <= ch <= 'Z':
            # Uppercase letter
            # Convert to 0-25, shift, and convert back
            shifted = (ord(ch) - ord('A') - key) % 26
            result += chr(shifted + ord('A'))
        elif 'a' <= ch <= 'z':
            # Lowercase letter
            shifted = (ord(ch) - ord('a') - key) % 26
            result += chr(shifted + ord('a'))
        else:
            # Non-alphabetic characters are not changed
            result += ch

    return result


def break_shift_cipher(ciphertext):
    print("Trying all possible keys (0 to 25):\n")
    for key in range(26):
        decrypted = decrypt_with_key(ciphertext, key)
        print(f"Key = {key:2d} -> {decrypted}")


def main():
    print("=== Break Shift (Caesar) Cipher ===\n")
    ciphertext = input("Enter the ciphertext: ")
    print()
    break_shift_cipher(ciphertext)


if __name__ == "__main__":
    main()
