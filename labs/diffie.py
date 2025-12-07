# Diffie-Hellman Key Exchange - Simple Demo

# 1. Publicly known prime (p) and primitive root (g)
p = 23       # prime number
g = 5        # primitive root modulo p

print("Publicly known values:")
print(f"Prime (p) = {p}")
print(f"Generator (g) = {g}")
print()

# 2. Alice chooses a private key a
a = 6        # Alice's private key (keep secret)
A = pow(g, a, p)   # Alice's public key A = g^a mod p
print("Alice's side:")
print(f"Alice's private key (a) = {a}")
print(f"Alice's public key (A = g^a mod p) = {A}")
print()

# 3. Bob chooses a private key b
b = 15       # Bob's private key (keep secret)
B = pow(g, b, p)   # Bob's public key B = g^b mod p
print("Bob's side:")
print(f"Bob's private key (b) = {b}")
print(f"Bob's public key (B = g^b mod p) = {B}")
print()

# 4. Exchange public keys A and B over the network (insecure channel)

# 5. Both compute the shared secret key

# Alice computes: K = B^a mod p
shared_key_alice = pow(B, a, p)

# Bob computes: K = A^b mod p
shared_key_bob = pow(A, b, p)

print("After exchanging public keys:")
print(f"Shared key computed by Alice (K = B^a mod p) = {shared_key_alice}")
print(f"Shared key computed by Bob   (K = A^b mod p) = {shared_key_bob}")
print()

if shared_key_alice == shared_key_bob:
    print(f"Key exchange successful! Shared secret key = {shared_key_alice}")
else:
    print("Key exchange failed, keys do not match.")
