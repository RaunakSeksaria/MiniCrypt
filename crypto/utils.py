"""
crypto/utils.py — Common utility functions used across all modules.

Provides:
  - Modular arithmetic (mod_exp, egcd, mod_inverse)
  - Byte manipulation (xor_bytes, int_to_bytes, bytes_to_int)
  - Random byte generation (random_bytes, random_int)
  - PKCS#7 padding/unpadding

NO external crypto libraries. Only os.urandom and Python built-in int.
"""

import os

# ---------------------------------------------------------------------------
# Modular Arithmetic
# ---------------------------------------------------------------------------

def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Square-and-multiply modular exponentiation: base^exp mod mod.
    Implemented from scratch — does NOT use Python's pow(base, exp, mod).
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        # If exp is odd, multiply result by base
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def egcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a: int, m: int) -> int:
    """
    Compute modular multiplicative inverse of a modulo m.
    Returns x such that (a * x) % m == 1.
    Raises ValueError if gcd(a, m) != 1.
    """
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {g}")
    return x % m


def gcd(a: int, b: int) -> int:
    """Compute greatest common divisor using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a


# ---------------------------------------------------------------------------
# Byte Manipulation
# ---------------------------------------------------------------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays of equal length."""
    if len(a) != len(b):
        raise ValueError(f"xor_bytes: length mismatch ({len(a)} vs {len(b)})")
    return bytes(x ^ y for x, y in zip(a, b))


def int_to_bytes(n: int, length: int) -> bytes:
    """Convert a non-negative integer to a big-endian byte string of given length."""
    return n.to_bytes(length, byteorder='big')


def bytes_to_int(b: bytes) -> int:
    """Convert a big-endian byte string to a non-negative integer."""
    return int.from_bytes(b, byteorder='big')


def int_to_bytes_auto(n: int) -> bytes:
    """Convert integer to bytes with auto-detected length (minimum bytes needed)."""
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')


# ---------------------------------------------------------------------------
# Random Generation
# ---------------------------------------------------------------------------

def random_bytes(n: int) -> bytes:
    """Generate n cryptographically random bytes using OS-level randomness."""
    return os.urandom(n)


def random_int(low: int, high: int) -> int:
    """
    Generate a uniform random integer in [low, high] inclusive.
    Uses os.urandom for cryptographic quality.
    """
    if low > high:
        raise ValueError(f"random_int: low ({low}) > high ({high})")
    if low == high:
        return low
    range_size = high - low + 1
    # Number of bytes needed to cover the range
    num_bytes = (range_size.bit_length() + 7) // 8
    # Rejection sampling to avoid modular bias
    while True:
        rand_val = bytes_to_int(os.urandom(num_bytes))
        if rand_val < range_size:
            return low + rand_val


def random_bits(n: int) -> int:
    """Generate a random n-bit integer (the top bit is set to ensure n bits)."""
    if n <= 0:
        return 0
    num_bytes = (n + 7) // 8
    val = bytes_to_int(os.urandom(num_bytes))
    # Mask to exactly n bits
    val = val & ((1 << n) - 1)
    # Set the top bit to ensure n bits
    val |= (1 << (n - 1))
    return val


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------

def pad_pkcs7(data: bytes, block_size: int) -> bytes:
    """
    Apply PKCS#7 padding to data so its length is a multiple of block_size.
    Pads with bytes whose value equals the number of padding bytes added.
    Always adds at least 1 byte of padding (even if data is already aligned).
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad_pkcs7(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding. Validates the padding and raises ValueError if invalid.
    """
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError(f"Invalid PKCS#7 padding value: {pad_len}")
    # Verify all padding bytes are correct
    for i in range(1, pad_len + 1):
        if data[-i] != pad_len:
            raise ValueError(f"Invalid PKCS#7 padding at position {-i}")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# Bit Manipulation Helpers
# ---------------------------------------------------------------------------

def bits_to_bytes(bits: list) -> bytes:
    """Convert a list of 0/1 bits to bytes (MSB first, padded with zeros)."""
    # Pad to multiple of 8
    while len(bits) % 8 != 0:
        bits = [0] + bits
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def bytes_to_bits(data: bytes) -> list:
    """Convert bytes to a list of 0/1 bits (MSB first)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def get_bit(data: bytes, index: int) -> int:
    """Get the bit at the given index (0-indexed from MSB of first byte)."""
    byte_idx = index // 8
    bit_idx = 7 - (index % 8)
    return (data[byte_idx] >> bit_idx) & 1


# ---------------------------------------------------------------------------
# Display Helpers
# ---------------------------------------------------------------------------

def to_hex(data: bytes) -> str:
    """Convert bytes to hexadecimal string."""
    return data.hex()


def from_hex(hex_str: str) -> bytes:
    """Convert hexadecimal string to bytes."""
    return bytes.fromhex(hex_str)


def split_blocks(data: bytes, block_size: int) -> list:
    """Split data into blocks of block_size bytes."""
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]
