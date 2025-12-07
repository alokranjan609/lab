# AES-128 Encryption from scratch (single 16-byte block, ECB mode)

# ---------- Finite field operations (GF(2^8)) ----------

def gf_mul(a, b):
    """Multiply two bytes in GF(2^8) with AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return res

def gf_pow(a, power):
    """Exponentiation in GF(2^8)."""
    res = 1
    while power:
        if power & 1:
            res = gf_mul(res, a)
        a = gf_mul(a, a)
        power >>= 1
    return res

def gf_inv(a):
    """Multiplicative inverse in GF(2^8). 0 maps to 0."""
    if a == 0:
        return 0
    # In GF(2^8), a^255 = 1 for non-zero a, so inverse is a^254
    return gf_pow(a, 254)

# ---------- S-Box generation (SubBytes uses this) ----------

def sub_byte_calc(a):
    """Compute AES S-box value for a single byte using inversion + affine transform."""
    x = gf_inv(a)
    y = x
    # affine transform
    for _ in range(1, 5):
        x = ((x << 1) | (x >> 7)) & 0xFF   # rotate left by 1 in 8 bits
        y ^= x
    return y ^ 0x63

# Generate full S-Box (256 entries)
S_BOX = [sub_byte_calc(i) for i in range(256)]

# ---------- Rcon for key expansion ----------

def rcon(i):
    """Round constant Rcon[i] (only first byte, others are 0)."""
    x = 1
    if i == 0:
        return 0
    while i > 1:
        x = gf_mul(x, 2)
        i -= 1
    return x

# ---------- Key expansion (AES-128: 16-byte key -> 176 bytes round keys) ----------

def sub_word(word):
    return [S_BOX[b] for b in word]

def rot_word(word):
    return word[1:] + word[:1]

def key_expansion(key_bytes):
    """Expand 16-byte key into 44 words (4 bytes each) for 11 round keys."""
    assert len(key_bytes) == 16
    Nk = 4   # words in key
    Nb = 4   # words in block
    Nr = 10  # number of rounds

    # w[i] is a word = list of 4 bytes
    w = [[0] * 4 for _ in range(Nb * (Nr + 1))]

    # first Nk words are just the key
    for i in range(Nk):
        w[i] = [key_bytes[4 * i + j] for j in range(4)]

    # remaining words
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1].copy()
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= rcon(i // Nk)
        w[i] = [(w[i - Nk][j] ^ temp[j]) for j in range(4)]

    return w  # list of 44 words

# ---------- State conversions ----------

def bytes_to_state(block):
    """Convert 16-byte block to 4x4 state matrix (column-major)."""
    assert len(block) == 16
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = block[i]
    return state

def state_to_bytes(state):
    """Convert 4x4 state matrix back to 16-byte block."""
    block = [0] * 16
    for col in range(4):
        for row in range(4):
            block[col * 4 + row] = state[row][col]
    return bytes(block)

# ---------- Core AES round transformations ----------

def add_round_key(state, w, round_num):
    """XOR state with round key (derived from w)."""
    for col in range(4):
        word = w[4 * round_num + col]
        for row in range(4):
            state[row][col] ^= word[row]

def sub_bytes(state):
    """Apply S-Box to each byte of state."""
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]

def shift_rows(state):
    """Cyclic left shift of each row r by r positions."""
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]

def mix_single_column(col):
    """Mix one column (4 bytes) using fixed matrix."""
    a0, a1, a2, a3 = col
    col[0] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
    col[1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
    col[2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
    col[3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)

def mix_columns(state):
    """Apply MixColumns to all 4 columns."""
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mix_single_column(col)
        for r in range(4):
            state[r][c] = col[r]

# ---------- AES-128 block encryption ----------

def aes_encrypt_block(plaintext_block, key_bytes):
    """Encrypt a 16-byte block with a 16-byte key using AES-128."""
    assert len(plaintext_block) == 16
    assert len(key_bytes) == 16

    w = key_expansion(key_bytes)
    state = bytes_to_state(list(plaintext_block))

    # Initial round
    add_round_key(state, w, 0)

    # Rounds 1 to 9
    for round_num in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, w, round_num)

    # Final round (no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w, 10)

    return state_to_bytes(state)

# ---------- Simple driver (single 16-byte block) ----------

def main():
    print("=== AES-128 from scratch (single 16-byte block, ECB) ===\n")

    plaintext = input("Enter plaintext (max 16 characters): ")
    key_text = input("Enter key (max 16 characters): ")

    # Convert to 16-byte blocks (pad with spaces if shorter, truncate if longer)
    plain_bytes = plaintext.encode('utf-8')[:16].ljust(16, b' ')
    key_bytes = key_text.encode('utf-8')[:16].ljust(16, b' ')

    ciphertext = aes_encrypt_block(plain_bytes, key_bytes)

    print("\nPlaintext (hex): ", plain_bytes.hex())
    print("Key       (hex): ", key_bytes.hex())
    print("Ciphertext(hex): ", ciphertext.hex())

if __name__ == "__main__":
    main()
