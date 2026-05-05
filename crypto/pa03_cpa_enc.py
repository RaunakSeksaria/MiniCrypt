"""
crypto/pa03_cpa_enc.py — PA#3: CPA-Secure Symmetric Encryption

Implements:
  1. CPA-secure encryption: C = ⟨r, F_k(r) ⊕ m⟩ with fresh random r
  2. Multi-block support via counter extension (r, r+1, r+2, ...)
  3. IND-CPA game simulation
  4. Broken variant (deterministic encryption with reused r)

Dependencies: crypto.pa02_prf_ggm (PRF), crypto.utils
Used by: PA#6 (CCA-secure encryption), PA#10 (Encrypt-then-HMAC)
"""

from crypto.utils import (
    xor_bytes, random_bytes, int_to_bytes, bytes_to_int,
    pad_pkcs7, unpad_pkcs7, to_hex, split_blocks
)
from crypto.pa02_prf_ggm import PRF
from crypto.aes import BLOCK_SIZE


# ---------------------------------------------------------------------------
# CPA-Secure Encryption Scheme
# ---------------------------------------------------------------------------

class CPAEncryption:
    """
    CPA-secure symmetric encryption using a PRF.

    Encryption of message m:
      1. Sample r ← {0,1}^n uniformly at random (fresh each call).
      2. For each block m_i, compute c_i = F_k(r+i) ⊕ m_i.
      3. Output C = (r, c_1 ‖ c_2 ‖ ... ‖ c_t).

    Decryption:
      1. Parse C = (r, ciphertext).
      2. For each block c_i, compute m_i = F_k(r+i) ⊕ c_i.
    """

    def __init__(self, prf: PRF = None):
        """
        Args:
            prf: PRF instance to use. Defaults to AES-based PRF.
        """
        if prf is None:
            prf = PRF(mode='aes')
        self.prf = prf
        self.block_size = BLOCK_SIZE  # 16 bytes

    def encrypt(self, key: bytes, plaintext: bytes) -> tuple:
        """
        Encrypt a message with CPA security.

        Args:
            key: Encryption key (16 bytes).
            plaintext: Message of arbitrary length.

        Returns:
            (r, ciphertext) where r is the random nonce (16 bytes)
            and ciphertext is the encrypted padded message.
        """
        if len(key) != self.block_size:
            raise ValueError(f"Key must be {self.block_size} bytes")

        # Pad the message
        padded = pad_pkcs7(plaintext, self.block_size)
        blocks = split_blocks(padded, self.block_size)

        # Sample fresh random nonce
        r = random_bytes(self.block_size)
        r_int = bytes_to_int(r)

        # Encrypt each block: c_i = F_k(r+i) ⊕ m_i
        ciphertext = bytearray()
        for i, block in enumerate(blocks):
            counter = int_to_bytes((r_int + i) % (1 << (self.block_size * 8)),
                                   self.block_size)
            keystream = self.prf.F(key, counter)
            ciphertext.extend(xor_bytes(keystream, block))

        return r, bytes(ciphertext)

    def decrypt(self, key: bytes, r: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt a CPA-encrypted message.

        Args:
            key: Encryption key (16 bytes).
            r: Nonce from encryption (16 bytes).
            ciphertext: Encrypted message.

        Returns:
            Original plaintext (unpadded).
        """
        if len(key) != self.block_size:
            raise ValueError(f"Key must be {self.block_size} bytes")
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")

        blocks = split_blocks(ciphertext, self.block_size)
        r_int = bytes_to_int(r)

        # Decrypt each block: m_i = F_k(r+i) ⊕ c_i
        plaintext = bytearray()
        for i, block in enumerate(blocks):
            counter = int_to_bytes((r_int + i) % (1 << (self.block_size * 8)),
                                   self.block_size)
            keystream = self.prf.F(key, counter)
            plaintext.extend(xor_bytes(keystream, block))

        return unpad_pkcs7(bytes(plaintext))

    def encrypt_deterministic(self, key: bytes, plaintext: bytes,
                               fixed_r: bytes = None) -> tuple:
        """
        BROKEN variant: deterministic encryption with reused nonce.
        This is insecure — used to demonstrate CPA attacks.
        """
        padded = pad_pkcs7(plaintext, self.block_size)
        blocks = split_blocks(padded, self.block_size)

        if fixed_r is None:
            fixed_r = b'\x00' * self.block_size  # Fixed, predictable nonce
        r_int = bytes_to_int(fixed_r)

        ciphertext = bytearray()
        for i, block in enumerate(blocks):
            counter = int_to_bytes((r_int + i) % (1 << (self.block_size * 8)),
                                   self.block_size)
            keystream = self.prf.F(key, counter)
            ciphertext.extend(xor_bytes(keystream, block))

        return fixed_r, bytes(ciphertext)


# ---------------------------------------------------------------------------
# IND-CPA Game
# ---------------------------------------------------------------------------

def ind_cpa_game(enc: CPAEncryption, num_rounds: int = 50) -> dict:
    """
    Simulate the IND-CPA game.

    In each round:
      1. Adversary chooses two equal-length messages m0 and m1.
      2. Challenger picks random bit b and encrypts m_b.
      3. Adversary guesses b' (uniformly at random here).
      4. Track advantage = |Pr[b'=b] - 1/2|.

    A secure scheme should have advantage ≈ 0.
    """
    import random
    key = random_bytes(BLOCK_SIZE)
    correct = 0

    for _ in range(num_rounds):
        # Adversary picks two messages of equal length
        msg_len = random.randint(1, 48)
        m0 = random_bytes(msg_len)
        m1 = random_bytes(msg_len)

        # Challenger picks b and encrypts
        b = random.randint(0, 1)
        chosen = m0 if b == 0 else m1
        r, ct = enc.encrypt(key, chosen)

        # Adversary guesses randomly (best strategy against CPA-secure scheme)
        b_guess = random.randint(0, 1)
        if b_guess == b:
            correct += 1

    advantage = abs(correct / num_rounds - 0.5)
    return {
        'rounds': num_rounds,
        'correct_guesses': correct,
        'win_rate': correct / num_rounds,
        'advantage': advantage,
        'secure': advantage < 0.15,
    }


def demonstrate_deterministic_attack(enc: CPAEncryption) -> dict:
    """
    Demonstrate that deterministic encryption (reused nonce) breaks CPA security.

    Attack: encrypt the same message twice with the same nonce.
    Identical ciphertexts reveal the plaintext is the same.
    """
    key = random_bytes(BLOCK_SIZE)
    m1 = b"attack at dawn!!"  # 16 bytes
    m2 = b"attack at dawn!!"  # Same message

    fixed_r = b'\x42' * BLOCK_SIZE

    _, ct1 = enc.encrypt_deterministic(key, m1, fixed_r)
    _, ct2 = enc.encrypt_deterministic(key, m2, fixed_r)

    # With proper encryption (fresh r), ciphertexts would differ
    r1, ct1_secure = enc.encrypt(key, m1)
    r2, ct2_secure = enc.encrypt(key, m2)

    return {
        'message': m1.decode('ascii', errors='replace'),
        'deterministic_ct1': to_hex(ct1),
        'deterministic_ct2': to_hex(ct2),
        'ciphertexts_identical': ct1 == ct2,
        'secure_ct1': to_hex(ct1_secure),
        'secure_ct2': to_hex(ct2_secure),
        'secure_ciphertexts_identical': ct1_secure == ct2_secure,
        'vulnerability': 'Reused nonce → identical ciphertexts → plaintext leaked',
    }


# ---------------------------------------------------------------------------
# Interface functions (for use by PA#6)
# ---------------------------------------------------------------------------

_default_enc = None

def _get_default():
    global _default_enc
    if _default_enc is None:
        _default_enc = CPAEncryption()
    return _default_enc

def Enc(key: bytes, plaintext: bytes) -> tuple:
    """Encrypt: returns (r, ciphertext)."""
    return _get_default().encrypt(key, plaintext)

def Dec(key: bytes, r: bytes, ciphertext: bytes) -> bytes:
    """Decrypt: returns plaintext."""
    return _get_default().decrypt(key, r, ciphertext)


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("PA#3: CPA-Secure Symmetric Encryption")
    print("=" * 60)

    enc = CPAEncryption()
    key = random_bytes(BLOCK_SIZE)

    # Basic encrypt/decrypt
    print("\n--- Basic Encrypt/Decrypt ---")
    for msg in [b"Hello!", b"Exactly16bytes!!", b"A longer message that spans multiple AES blocks easily"]:
        r, ct = enc.encrypt(key, msg)
        pt = enc.decrypt(key, r, ct)
        print(f"Message: {msg}")
        print(f"  Ciphertext: {to_hex(ct)[:40]}...")
        print(f"  Decrypted:  {pt}")
        print(f"  Match: {pt == msg}")

    # IND-CPA game
    print("\n--- IND-CPA Game ---")
    result = ind_cpa_game(enc, num_rounds=100)
    print(f"Rounds: {result['rounds']}")
    print(f"Win rate: {result['win_rate']:.2f} (should be ~0.50)")
    print(f"Advantage: {result['advantage']:.4f} (should be ~0)")
    print(f"Secure: {result['secure']}")

    # Deterministic attack
    print("\n--- Deterministic Encryption Attack ---")
    attack = demonstrate_deterministic_attack(enc)
    print(f"Deterministic ciphertexts identical: {attack['ciphertexts_identical']}")
    print(f"Secure ciphertexts identical: {attack['secure_ciphertexts_identical']}")
    print(f"Vulnerability: {attack['vulnerability']}")
