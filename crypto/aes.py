"""
crypto/aes.py — Full AES-128 Implementation from Scratch

Implements the complete AES-128 block cipher:
  - SubBytes / InvSubBytes (S-Box lookup)
  - ShiftRows / InvShiftRows
  - MixColumns / InvMixColumns (GF(2^8) arithmetic)
  - AddRoundKey
  - Key Expansion (128-bit key → 11 round keys)
  - 10-round encryption and decryption

Block size: 128 bits (16 bytes)
Key size:   128 bits (16 bytes)

State layout: column-major flat list of 16 bytes.
  state[col*4 + row] = state_matrix[row][col]
  Indices 0-3 = column 0, indices 4-7 = column 1, etc.

This is a concrete PRP/PRF used throughout the project (PA#2, PA#4, etc.).
NO external crypto libraries used.
"""

# ---------------------------------------------------------------------------
# AES S-Box and Inverse S-Box (pre-computed lookup tables)
# ---------------------------------------------------------------------------

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# Round constants for key expansion
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ---------------------------------------------------------------------------
# GF(2^8) Arithmetic (for MixColumns)
# ---------------------------------------------------------------------------

def gf_mult(a: int, b: int) -> int:
    """
    Multiply two elements in GF(2^8) using the AES irreducible polynomial
    x^8 + x^4 + x^3 + x + 1 (0x11B).
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return result


# Pre-compute multiplication tables for the constants used in MixColumns
_MUL2 = [gf_mult(i, 2) for i in range(256)]
_MUL3 = [gf_mult(i, 3) for i in range(256)]
_MUL9 = [gf_mult(i, 9) for i in range(256)]
_MUL11 = [gf_mult(i, 11) for i in range(256)]
_MUL13 = [gf_mult(i, 13) for i in range(256)]
_MUL14 = [gf_mult(i, 14) for i in range(256)]


# ---------------------------------------------------------------------------
# AES State Operations
# ---------------------------------------------------------------------------
# The AES state is a 4×4 matrix of bytes, stored column-major:
#   state[col*4 + row] = state_matrix[row][col]
#
# Input bytes are read column-by-column into the state:
#   byte[0]  → state[0][0] (col 0, row 0) → index 0
#   byte[1]  → state[1][0] (col 0, row 1) → index 1
#   byte[2]  → state[2][0] (col 0, row 2) → index 2
#   byte[3]  → state[3][0] (col 0, row 3) → index 3
#   byte[4]  → state[0][1] (col 1, row 0) → index 4
#   ...
# So state flat index = col*4 + row = byte_index. It's identity mapping!

def _bytes_to_state(data: bytes) -> list:
    """Convert 16 bytes to AES state (column-major). This is just list(data)."""
    return list(data)


def _state_to_bytes(state: list) -> bytes:
    """Convert AES state back to 16 bytes."""
    return bytes(state)


def _sub_bytes(state: list) -> list:
    """Apply S-Box substitution to each byte of the state."""
    return [S_BOX[b] for b in state]


def _inv_sub_bytes(state: list) -> list:
    """Apply inverse S-Box substitution to each byte of the state."""
    return [INV_S_BOX[b] for b in state]


def _shift_rows(state: list) -> list:
    """
    Shift rows of the state matrix left:
      Row 0: no shift
      Row 1: left shift by 1
      Row 2: left shift by 2
      Row 3: left shift by 3

    In column-major layout state[col*4 + row]:
      Row r occupies indices {0*4+r, 1*4+r, 2*4+r, 3*4+r} = {r, 4+r, 8+r, 12+r}
    """
    s = list(state)
    # Row 0: no change (indices 0, 4, 8, 12)

    # Row 1: shift left by 1 (indices 1, 5, 9, 13)
    s[1], s[5], s[9], s[13] = state[5], state[9], state[13], state[1]

    # Row 2: shift left by 2 (indices 2, 6, 10, 14)
    s[2], s[6], s[10], s[14] = state[10], state[14], state[2], state[6]

    # Row 3: shift left by 3 = right by 1 (indices 3, 7, 11, 15)
    s[3], s[7], s[11], s[15] = state[15], state[3], state[7], state[11]

    return s


def _inv_shift_rows(state: list) -> list:
    """
    Inverse ShiftRows — shift rows to the right.
    """
    s = list(state)
    # Row 1: shift right by 1
    s[1], s[5], s[9], s[13] = state[13], state[1], state[5], state[9]

    # Row 2: shift right by 2
    s[2], s[6], s[10], s[14] = state[10], state[14], state[2], state[6]

    # Row 3: shift right by 3 = left by 1
    s[3], s[7], s[11], s[15] = state[7], state[11], state[15], state[3]

    return s


def _mix_columns(state: list) -> list:
    """
    MixColumns: multiply each column by the fixed polynomial in GF(2^8).
    Column j occupies state[j*4 + 0..3] = rows 0..3 of that column.

    Matrix:  [2 3 1 1]
             [1 2 3 1]
             [1 1 2 3]
             [3 1 1 2]
    """
    s = list(state)
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i], state[i+1], state[i+2], state[i+3]
        s[i]   = _MUL2[a0] ^ _MUL3[a1] ^ a2       ^ a3
        s[i+1] = a0        ^ _MUL2[a1] ^ _MUL3[a2] ^ a3
        s[i+2] = a0        ^ a1        ^ _MUL2[a2] ^ _MUL3[a3]
        s[i+3] = _MUL3[a0] ^ a1        ^ a2        ^ _MUL2[a3]
    return s


def _inv_mix_columns(state: list) -> list:
    """
    Inverse MixColumns.
    Matrix:  [14 11 13  9]
             [ 9 14 11 13]
             [13  9 14 11]
             [11 13  9 14]
    """
    s = list(state)
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i], state[i+1], state[i+2], state[i+3]
        s[i]   = _MUL14[a0] ^ _MUL11[a1] ^ _MUL13[a2] ^ _MUL9[a3]
        s[i+1] = _MUL9[a0]  ^ _MUL14[a1] ^ _MUL11[a2] ^ _MUL13[a3]
        s[i+2] = _MUL13[a0] ^ _MUL9[a1]  ^ _MUL14[a2] ^ _MUL11[a3]
        s[i+3] = _MUL11[a0] ^ _MUL13[a1] ^ _MUL9[a2]  ^ _MUL14[a3]
    return s


def _add_round_key(state: list, round_key: list) -> list:
    """XOR the state with a round key (both are 16-element lists)."""
    return [s ^ k for s, k in zip(state, round_key)]


# ---------------------------------------------------------------------------
# Key Expansion
# ---------------------------------------------------------------------------

def _key_expansion(key: bytes) -> list:
    """
    Expand a 128-bit (16-byte) key into 11 round keys (176 bytes total).
    Returns a list of 11 round keys, each a list of 16 ints in column-major order.
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires exactly 16-byte key, got {len(key)}")

    # Convert key bytes to 4 words of 4 bytes each (column-major: word i = column i)
    # key bytes 0-3 = word 0 = column 0, key bytes 4-7 = word 1 = column 1, etc.
    w = []
    for i in range(4):
        w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])

    # Expand to 44 words
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            # RotWord: rotate left by 1 byte
            temp = temp[1:] + temp[:1]
            # SubWord: apply S-Box
            temp = [S_BOX[b] for b in temp]
            # XOR with round constant
            temp[0] ^= RCON[i // 4 - 1]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])

    # Convert words to round keys in column-major state format
    # Round key r uses words w[4r], w[4r+1], w[4r+2], w[4r+3]
    # Each word is a column (4 rows).
    # In our flat layout: rk[col*4 + row] = w[4r + col][row]
    round_keys = []
    for r in range(11):
        rk = []
        for col in range(4):
            rk.extend(w[r * 4 + col])  # append 4 bytes of this column
        round_keys.append(rk)

    return round_keys


# ---------------------------------------------------------------------------
# AES-128 Encrypt / Decrypt (single 128-bit block)
# ---------------------------------------------------------------------------

def aes_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt a single 16-byte block with AES-128.

    Args:
        plaintext: 16 bytes of plaintext
        key: 16 bytes of key

    Returns:
        16 bytes of ciphertext
    """
    if len(plaintext) != 16:
        raise ValueError(f"AES block must be 16 bytes, got {len(plaintext)}")

    round_keys = _key_expansion(key)
    state = _bytes_to_state(plaintext)

    # Initial round key addition
    state = _add_round_key(state, round_keys[0])

    # Rounds 1–9 (full rounds)
    for r in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])

    # Round 10 (no MixColumns)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])

    return _state_to_bytes(state)


def aes_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt a single 16-byte block with AES-128.

    Args:
        ciphertext: 16 bytes of ciphertext
        key: 16 bytes of key

    Returns:
        16 bytes of plaintext
    """
    if len(ciphertext) != 16:
        raise ValueError(f"AES block must be 16 bytes, got {len(ciphertext)}")

    round_keys = _key_expansion(key)
    state = _bytes_to_state(ciphertext)

    # Initial round (inverse of round 10)
    state = _add_round_key(state, round_keys[10])
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)

    # Rounds 9–1 (inverse full rounds)
    for r in range(9, 0, -1):
        state = _add_round_key(state, round_keys[r])
        state = _inv_mix_columns(state)
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)

    # Final round key
    state = _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)


# ---------------------------------------------------------------------------
# Convenience: AES as a PRF / PRP
# ---------------------------------------------------------------------------

BLOCK_SIZE = 16  # AES block size in bytes
KEY_SIZE = 16    # AES-128 key size in bytes


def aes_prf(key: bytes, x: bytes) -> bytes:
    """Use AES-128 as a PRF: F_k(x) = AES_k(x)."""
    return aes_encrypt_block(x, key)


def aes_prp_inverse(key: bytes, y: bytes) -> bytes:
    """Use AES-128 inverse as PRP^{-1}: F_k^{-1}(y) = AES_k^{-1}(y)."""
    return aes_decrypt_block(y, key)


def aes_owf(key: bytes) -> bytes:
    """
    AES as a compression OWF (Davies-Meyer):
    f(k) = AES_k(0^128) ⊕ k
    """
    from crypto.utils import xor_bytes
    zero_block = b'\x00' * 16
    return xor_bytes(aes_encrypt_block(zero_block, key), key)
