# Elliptic Curve Digital Signature Algorithm (ECDSA) from scratch
# Toy example over a small curve: NOT secure, but perfect for lab/demo.

import hashlib
import random
import math

# Elliptic curve: y^2 = x^3 + a*x + b (mod p)
p = 23
a = 1
b = 1

# Base point G on the curve (must satisfy the curve equation)
G = (9, 7)

# Point at infinity (identity element)
O = None

# Order of G on this curve (computed beforehand)
n = 28  # In real ECDSA, n is a large prime. Here it's a small number for demo.


# ---------- Basic elliptic curve operations ----------

def is_on_curve(P):
    """Check if point P lies on the elliptic curve."""
    if P is None:
        return True
    x, y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0


def inv_mod(k, mod):
    """Modular inverse using Python's pow (works if gcd(k, mod) == 1)."""
    return pow(k, -1, mod)


def point_add(P, Q):
    """Add two points P and Q on the elliptic curve."""
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # P + (-P) = O
    if x1 == x2 and (y1 + y2) % p == 0:
        return O

    if P != Q:
        # Slope for P != Q
        lam = ((y2 - y1) * inv_mod((x2 - x1) % p, p)) % p
    else:
        # P == Q: point doubling
        lam = ((3 * x1 * x1 + a) * inv_mod((2 * y1) % p, p)) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return (x3, y3)


def scalar_mult(k, P):
    """Compute k * P using double-and-add algorithm."""
    R = O            # result
    addend = P

    while k > 0:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)  # point doubling
        k >>= 1

    return R


# ---------- ECDSA: sign and verify ----------

def hash_to_int(message):
    """Hash the message using SHA-256 and convert to integer modulo n."""
    h = hashlib.sha256(message.encode('utf-8')).digest()
    e = int.from_bytes(h, 'big') % n
    if e == 0:
        e = 1  # avoid zero
    return e


def sign_message(message, d_priv):
    """
    Sign 'message' using private key d_priv.
    Returns (r, s).
    """
    e = hash_to_int(message)

    while True:
        # choose random k in [1, n-1] that is invertible mod n
        k = random.randint(1, n - 1)
        if math.gcd(k, n) != 1:
            continue

        R = scalar_mult(k, G)
        if R is None:
            continue

        x1, _ = R
        r = x1 % n
        if r == 0:
            continue

        k_inv = inv_mod(k, n)
        s = (k_inv * (e + d_priv * r)) % n
        # s must be non-zero and invertible mod n
        if s == 0 or math.gcd(s, n) != 1:
            continue

        return r, s


def verify_signature(message, r, s, Q_pub):
    """
    Verify signature (r, s) on 'message' using public key Q_pub.
    Returns True if valid, False otherwise.
    """
    if not (1 <= r < n and 1 <= s < n):
        return False

    e = hash_to_int(message)
    try:
        w = inv_mod(s, n)
    except ValueError:
        return False

    u1 = (e * w) % n
    u2 = (r * w) % n

    # X = u1 * G + u2 * Q
    X = point_add(scalar_mult(u1, G), scalar_mult(u2, Q_pub))
    if X is None:
        return False

    x2, _ = X
    v = x2 % n

    return v == r


# ---------- Demo / driver code ----------

def main():
    print("=== Elliptic Curve Digital Signature Algorithm (ECDSA) - From Scratch ===\n")
    print(f"Curve: y^2 = x^3 + {a}x + {b} (mod {p})")
    print(f"Base point G = {G}")
    print(f"Order of G (n) = {n}\n")

    if not is_on_curve(G):
        print("Error: base point G is not on the curve!")
        return

    # 1. Get message and private key from user
    message = input("Enter message to sign: ")
    d_priv = int(input("Enter private key d (integer): "))

    # 2. Compute public key Q = d * G
    Q_pub = scalar_mult(d_priv, G)
    print(f"\nPublic key Q = d * G = {Q_pub}")

    # 3. Sign the message
    r, s = sign_message(message, d_priv)
    print("\n=== Signature ===")
    print(f"r = {r}")
    print(f"s = {s}")

    # 4. Verify the signature
    print("\n=== Verifying signature ===")
    valid = verify_signature(message, r, s, Q_pub)
    if valid:
        print("Signature is VALID ✅")
    else:
        print("Signature is INVALID ❌")


if __name__ == "__main__":
    main()
