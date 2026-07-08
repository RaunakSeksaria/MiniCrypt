"""
crypto/rsa.py — Textbook RSA + PKCS#1 v1.5

Implements:
  1. RSA key generation using Miller-Rabin
  2. Textbook RSA encryption/decryption (square-and-multiply)
  3. PKCS#1 v1.5 padding (0x00 0x02 PS 0x00 M)
  4. Determinism attack demo
  5. Simplified Bleichenbacher oracle demo

Dependencies: crypto.miller_rabin, crypto.utils
Used by: (CRT), (signatures), (OT)
"""

from crypto.utils import (
    mod_exp, mod_inverse, random_bytes, bytes_to_int, int_to_bytes,
    to_hex, random_int
)
from crypto.miller_rabin import gen_prime


# ---------------------------------------------------------------------------
# RSA Key Generation
# ---------------------------------------------------------------------------

class RSAKeyPair:
    """RSA key pair container."""

    def __init__(self, n, e, d, p=None, q=None):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.bits = n.bit_length()

        # CRT components for 
        if p and q:
            self.dp = d % (p - 1)
            self.dq = d % (q - 1)
            self.q_inv = mod_inverse(q, p)


def rsa_keygen(bits: int = 512, e: int = 65537) -> RSAKeyPair:
    """
    Generate an RSA key pair.

    Args:
        bits: Total modulus bit length (p and q are bits/2 each).
        e: Public exponent (default 65537).

    Returns:
        RSAKeyPair with (n, e, d, p, q).
    """
    half_bits = bits // 2

    while True:
        p, _ = gen_prime(half_bits)
        q, _ = gen_prime(half_bits)

        if p == q:
            continue

        n = p * q
        phi_n = (p - 1) * (q - 1)

        # Check gcd(e, phi_n) == 1
        from crypto.utils import gcd
        if gcd(e, phi_n) != 1:
            continue

        d = mod_inverse(e, phi_n)
        return RSAKeyPair(n, e, d, p, q)


# ---------------------------------------------------------------------------
# Textbook RSA
# ---------------------------------------------------------------------------

def rsa_encrypt(pk_n: int, pk_e: int, m: int) -> int:
    """
    Textbook RSA encryption: c = m^e mod n.

    Args:
        pk_n: Public modulus n.
        pk_e: Public exponent e.
        m: Plaintext integer (0 ≤ m < n).

    Returns:
        Ciphertext integer c.
    """
    if m < 0 or m >= pk_n:
        raise ValueError(f"Message must be in [0, n): m={m}, n={pk_n}")
    return mod_exp(m, pk_e, pk_n)


def rsa_decrypt(sk_d: int, pk_n: int, c: int) -> int:
    """
    Textbook RSA decryption: m = c^d mod n.

    Args:
        sk_d: Private exponent d.
        pk_n: Public modulus n.
        c: Ciphertext integer.

    Returns:
        Plaintext integer m.
    """
    return mod_exp(c, sk_d, pk_n)


def rsa_encrypt_bytes(pk_n: int, pk_e: int, message: bytes) -> int:
    """Encrypt a byte string using textbook RSA."""
    m = bytes_to_int(message)
    if m >= pk_n:
        raise ValueError(f"Message too large for key: {m.bit_length()} bits > "
                         f"{pk_n.bit_length()} bits")
    return rsa_encrypt(pk_n, pk_e, m)


def rsa_decrypt_bytes(sk_d: int, pk_n: int, c: int, msg_len: int) -> bytes:
    """Decrypt a ciphertext to bytes."""
    m = rsa_decrypt(sk_d, pk_n, c)
    return int_to_bytes(m, msg_len)


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 Padding
# ---------------------------------------------------------------------------

def pkcs15_pad(message: bytes, key_byte_length: int) -> bytes:
    """
    Apply PKCS#1 v1.5 encryption padding.

    Format: 0x00 ‖ 0x02 ‖ PS ‖ 0x00 ‖ M

    where PS is at least 8 random non-zero bytes.

    Args:
        message: Plaintext bytes.
        key_byte_length: k = byte length of the RSA modulus n.

    Returns:
        Padded message of exactly key_byte_length bytes.
    """
    max_msg_len = key_byte_length - 11  # 2 bytes header + 8 min PS + 1 separator
    if len(message) > max_msg_len:
        raise ValueError(f"Message too long for PKCS#1 v1.5: {len(message)} > {max_msg_len}")

    ps_len = key_byte_length - len(message) - 3
    # Generate random non-zero padding
    ps = bytearray()
    while len(ps) < ps_len:
        byte = random_bytes(1)
        if byte != b'\x00':
            ps.extend(byte)

    return b'\x00\x02' + bytes(ps) + b'\x00' + message


def pkcs15_unpad(padded: bytes) -> bytes:
    """
    Remove PKCS#1 v1.5 padding.

    Returns:
        Original message bytes.

    Raises:
        ValueError: If padding is malformed.
    """
    if len(padded) < 11:
        raise ValueError("Padded message too short")
    if padded[0] != 0x00 or padded[1] != 0x02:
        raise ValueError("Invalid PKCS#1 v1.5 header")

    # Find the 0x00 separator after PS
    sep_idx = None
    for i in range(2, len(padded)):
        if padded[i] == 0x00:
            sep_idx = i
            break

    if sep_idx is None:
        raise ValueError("No 0x00 separator found")
    if sep_idx < 10:  # PS must be at least 8 bytes (positions 2-9)
        raise ValueError("PS too short (< 8 bytes)")

    return padded[sep_idx + 1:]


def pkcs15_encrypt(pk_n: int, pk_e: int, message: bytes) -> int:
    """PKCS#1 v1.5 RSA encryption."""
    k = (pk_n.bit_length() + 7) // 8
    padded = pkcs15_pad(message, k)
    m = bytes_to_int(padded)
    return rsa_encrypt(pk_n, pk_e, m)


def pkcs15_decrypt(sk_d: int, pk_n: int, c: int) -> bytes:
    """PKCS#1 v1.5 RSA decryption."""
    k = (pk_n.bit_length() + 7) // 8
    m = rsa_decrypt(sk_d, pk_n, c)
    padded = int_to_bytes(m, k)
    return pkcs15_unpad(padded)


# ---------------------------------------------------------------------------
# Attack Demos
# ---------------------------------------------------------------------------

def determinism_attack_demo(bits: int = 512) -> dict:
    """
    Demonstrate that textbook RSA is deterministic.
    Encrypting the same plaintext always yields the same ciphertext.
    """
    kp = rsa_keygen(bits)
    m = 42

    c1 = rsa_encrypt(kp.n, kp.e, m)
    c2 = rsa_encrypt(kp.n, kp.e, m)

    return {
        'message': m,
        'c1': c1,
        'c2': c2,
        'identical': c1 == c2,
        'vulnerability': 'Textbook RSA is deterministic: Enc(m) always yields same c. '
                         'Adversary can verify plaintext guesses.',
    }


def multiplicative_homomorphism_demo(bits: int = 512) -> dict:
    """
    Demonstrate RSA's multiplicative homomorphism:
    Enc(m1) * Enc(m2) mod n = Enc(m1 * m2 mod n)
    """
    kp = rsa_keygen(bits)
    m1, m2 = 7, 11

    c1 = rsa_encrypt(kp.n, kp.e, m1)
    c2 = rsa_encrypt(kp.n, kp.e, m2)

    c_product = (c1 * c2) % kp.n
    m_product = rsa_decrypt(kp.d, kp.n, c_product)

    return {
        'm1': m1, 'm2': m2,
        'm1_m2': m1 * m2,
        'c1_c2_decrypted': m_product,
        'homomorphic': m_product == (m1 * m2) % kp.n,
        'vulnerability': 'Enc(m1)·Enc(m2) = Enc(m1·m2) → ciphertext malleability',
    }


def bleichenbacher_oracle_demo(bits: int = 256) -> dict:
    """
    Simplified Bleichenbacher PKCS#1 v1.5 padding oracle demo.

    The oracle tells the attacker whether decrypted padding starts with 0x00 0x02.
    We simulate this to show how it leaks information.
    """
    kp = rsa_keygen(bits)
    k = (kp.n.bit_length() + 7) // 8

    def padding_oracle(c: int) -> bool:
        """Returns True if the decrypted plaintext has valid PKCS#1 v1.5 format."""
        m = rsa_decrypt(kp.d, kp.n, c)
        padded = int_to_bytes(m, k)
        return padded[0] == 0x00 and padded[1] == 0x02

    # Encrypt a message
    message = b"Hi"
    c_star = pkcs15_encrypt(kp.n, kp.e, message)

    # Demonstrate the oracle
    oracle_on_valid = padding_oracle(c_star)

    # Try random ciphertexts
    oracle_accepts = 0
    trials = 100
    for _ in range(trials):
        random_c = random_int(2, kp.n - 1)
        if padding_oracle(random_c):
            oracle_accepts += 1

    return {
        'valid_ciphertext_oracle': oracle_on_valid,  # Should be True
        'random_oracle_accepts': oracle_accepts,
        'random_trials': trials,
        'accept_rate': oracle_accepts / trials,
        'vulnerability': 'Padding oracle reveals whether decryption starts with 0x0002. '
                         'Full attack recovers plaintext in ~1M queries for 1024-bit key.',
    }


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("Textbook RSA + PKCS#1 v1.5")
    print("=" * 60)

    # Key generation
    print("\n--- Key Generation (512-bit) ---")
    kp = rsa_keygen(512)
    print(f"n = {kp.n}")
    print(f"e = {kp.e}")
    print(f"d = {kp.d}")
    print(f"Bits: {kp.bits}")

    # Textbook RSA
    print("\n--- Textbook RSA ---")
    m = 42
    c = rsa_encrypt(kp.n, kp.e, m)
    m2 = rsa_decrypt(kp.d, kp.n, c)
    print(f"Encrypt({m}) = {c}")
    print(f"Decrypt(c) = {m2}")
    print(f"Match: {m == m2}")

    # PKCS#1 v1.5
    print("\n--- PKCS#1 v1.5 ---")
    msg = b"Hello RSA!"
    c = pkcs15_encrypt(kp.n, kp.e, msg)
    pt = pkcs15_decrypt(kp.d, kp.n, c)
    print(f"Message: {msg}")
    print(f"Decrypted: {pt}")
    print(f"Match: {msg == pt}")

    # Attacks
    print("\n--- Determinism Attack ---")
    det = determinism_attack_demo(256)
    print(f"Same ciphertext: {det['identical']}")

    print("\n--- Multiplicative Homomorphism ---")
    hom = multiplicative_homomorphism_demo(256)
    print(f"{hom['m1']}×{hom['m2']} = {hom['m1_m2']}, "
          f"Decrypted product: {hom['c1_c2_decrypted']}, "
          f"Homomorphic: {hom['homomorphic']}")

    print("\n--- Bleichenbacher Oracle (simplified) ---")
    bl = bleichenbacher_oracle_demo(256)
    print(f"Valid ciphertext passes oracle: {bl['valid_ciphertext_oracle']}")
    print(f"Random ciphertexts accepted: {bl['random_oracle_accepts']}/{bl['random_trials']}")
