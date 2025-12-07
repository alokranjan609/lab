# Elliptic Curve Diffie–Hellman (ECDH) key exchange - from scratch (toy curve)

# Curve: y^2 = x^3 + a*x + b (mod p)
# We use a small prime field just for demonstration:
p = 23           # prime
a = 1
b = 1

# Base point G on the curve (must satisfy the curve equation)
G = (9, 7)       # this point lies on y^2 = x^3 + x + 1 (mod 23)

# Point at infinity (identity element)
O = None


def is_on_curve(P):
    """Check if point P lies on the elliptic curve."""
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0


def inv_mod(k, p):
    """Modular inverse: returns x such that (k * x) % p == 1."""
    # Python 3.8+ supports pow with negative exponent mod p
    return pow(k, -1, p)


def point_add(P, Q):
    """Add two points P and Q on the elliptic curve."""
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # If P == -Q, result is point at infinity
    if x1 == x2 and (y1 + y2) % p == 0:
        return O

    if P != Q:
        # Slope for P != Q
        lam = ((y2 - y1) * inv_mod((x2 - x1) % p, p)) % p
    else:
        # P == Q: use tangent slope (point doubling)
        lam = ((3 * x1 * x1 + a) * inv_mod((2 * y1) % p, p)) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return (x3, y3)


def scalar_mult(k, P):
    """Compute k * P using double-and-add algorithm."""
    R = O           # result starts at point at infinity
    addend = P

    while k > 0:
        if k & 1:   # if least significant bit is 1
            R = point_add(R, addend)
        addend = point_add(addend, addend)  # point doubling
        k >>= 1      # shift k right by 1 bit

    return R


def main():
    print("=== Elliptic Curve Diffie–Hellman (ECDH) Demo ===\n")
    print(f"Curve: y^2 = x^3 + {a}x + {b} (mod {p})")
    print(f"Base point G = {G}")
    print()

    # Check base point
    if not is_on_curve(G):
        print("Error: Base point G is not on the curve!")
        return

    # 1. Alice chooses private key a_priv
    a_priv = int(input("Enter Alice's private key (integer): "))
    A_pub = scalar_mult(a_priv, G)
    print(f"Alice's public key A = a * G = {A_pub}")

    # 2. Bob chooses private key b_priv
    b_priv = int(input("\nEnter Bob's private key (integer): "))
    B_pub = scalar_mult(b_priv, G)
    print(f"Bob's public key B = b * G = {B_pub}")

    # 3. Exchange public keys A_pub and B_pub (over insecure channel)

    # 4. Compute shared secret

    # Alice computes S_A = a * B
    S_A = scalar_mult(a_priv, B_pub)

    # Bob computes S_B = b * A
    S_B = scalar_mult(b_priv, A_pub)

    print("\n=== Shared secret computation ===")
    print(f"Shared secret computed by Alice: {S_A}")
    print(f"Shared secret computed by Bob  : {S_B}")

    if S_A == S_B:
        print("\nKey exchange successful!")
        # Often we use just x-coordinate as the key material:
        if S_A is not None:
            shared_key = S_A[0]
            print(f"Derived shared key (x-coordinate) = {shared_key}")
    else:
        print("\nKey exchange failed! Shared points do not match.")


if __name__ == "__main__":
    main()
