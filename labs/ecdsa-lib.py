# Elliptic Curve Digital Signature Algorithm (ECDSA) demo using Python

from ecdsa import SigningKey, SECP256k1
import hashlib

def main():
    print("=== Elliptic Curve Digital Signature Algorithm (ECDSA) Demo ===\n")

    # 1. Take message from user
    message = input("Enter message to sign: ")
    message_bytes = message.encode('utf-8')

    # 2. Hash the message (using SHA-256)
    msg_hash = hashlib.sha256(message_bytes).digest()
    print("\nSHA-256 hash of message (hex):", msg_hash.hex())

    # 3. Generate EC key pair (private + public)
    # Curve: SECP256k1 (Bitcoin's curve, standard for demos)
    sk = SigningKey.generate(curve=SECP256k1)   # private key
    vk = sk.verifying_key                       # public key

    print("\n=== Key Pair ===")
    print("Private key (hex):", sk.to_string().hex())
    print("Public key  (hex):", vk.to_string().hex())

    # 4. Sign the message hash
    signature = sk.sign(msg_hash)
    print("\n=== Signature ===")
    print("Signature (hex):", signature.hex())

    # 5. Verify the signature
    try:
        vk.verify(signature, msg_hash)
        print("\nSignature verification: SUCCESS (valid signature)")
    except:
        print("\nSignature verification: FAILED (invalid signature)")


if __name__ == "__main__":
    main()
