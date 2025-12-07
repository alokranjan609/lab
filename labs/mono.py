# Break Monoalphabetic Substitution Cipher using Frequency Analysis

from collections import Counter

# English letter frequency order (most common to least common)
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

def analyze_frequency(ciphertext):
    # Keep only letters for frequency count (case-insensitive)
    letters_only = [ch.upper() for ch in ciphertext if ch.isalpha()]
    counts = Counter(letters_only)

    # Sort cipher letters by frequency (highest first)
    sorted_cipher_letters = [item[0] for item in counts.most_common()]
    return sorted_cipher_letters, counts


def build_mapping(sorted_cipher_letters):
    """
    Build a simple frequency-based mapping:
    most frequent cipher letter -> 'E',
    second most -> 'T', etc.
    """
    mapping = {}

    for i, cipher_letter in enumerate(sorted_cipher_letters):
        if i < len(ENGLISH_FREQ_ORDER):
            plain_letter = ENGLISH_FREQ_ORDER[i]
            mapping[cipher_letter] = plain_letter
        else:
            # if more letters than our frequency list, just map to itself
            mapping[cipher_letter] = cipher_letter

    return mapping


def decrypt_with_mapping(ciphertext, mapping):
    result = ""

    for ch in ciphertext:
        if ch.isalpha():
            is_upper = ch.isupper()
            c = ch.upper()
            if c in mapping:
                p = mapping[c]
            else:
                p = c  # if no mapping, leave as is

            # Restore case
            if not is_upper:
                p = p.lower()

            result += p
        else:
            # Non-letters are unchanged (spaces, punctuation, digits)
            result += ch

    return result


def main():
    print("=== Break Monoalphabetic Substitution Cipher (Frequency Analysis) ===\n")
    ciphertext = input("Enter the ciphertext: \n")

    # 1. Frequency analysis
    sorted_cipher_letters, counts = analyze_frequency(ciphertext)

    print("\nLetter frequencies in ciphertext:")
    for letter, count in counts.most_common():
        print(f"{letter} : {count}")

    print("\nCipher letters sorted by frequency:")
    print(" ".join(sorted_cipher_letters))

    # 2. Build initial mapping based on English frequency
    mapping = build_mapping(sorted_cipher_letters)

    print("\nInitial frequency-based mapping (cipher -> plain):")
    for c in sorted(mapping.keys()):
        print(f"{c} -> {mapping[c]}")

    # 3. Decrypt using this mapping
    decrypted_guess = decrypt_with_mapping(ciphertext, mapping)

    print("\n--- Decrypted guess (based on frequency) ---")
    print(decrypted_guess)


if __name__ == "__main__":
    main()
