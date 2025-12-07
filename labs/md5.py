# Program to compute MD5 and SHA1 hash digests using hashlib

import hashlib

def main():
    print("=== MD5 and SHA1 Hash Digest Generator ===\n")

    # Take input text from user
    text = input("Enter text to hash: ")

    # Convert text to bytes (hash functions work on bytes)
    data = text.encode('utf-8')

    # MD5 digest
    md5_hash = hashlib.md5()
    md5_hash.update(data)
    md5_digest = md5_hash.hexdigest()

    # SHA1 digest
    sha1_hash = hashlib.sha1()
    sha1_hash.update(data)
    sha1_digest = sha1_hash.hexdigest()

    print("\n--- Hash Digests ---")
    print("Input text     :", text)
    print("MD5 Digest     :", md5_digest)
    print("SHA1 Digest    :", sha1_digest)


if __name__ == "__main__":
    main()
