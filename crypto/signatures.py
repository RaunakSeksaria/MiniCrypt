"""
crypto/signatures.py — Digital Signatures

Implements:
  1. RSA-based signatures: Sign(sk, m) = H(m)^d mod N
  2. Hash-then-sign using DLP hash
  3. Verify: check H(m)^e ≡ σ^e (mod N)? No: check σ^e ≡ H(m) (mod N)
  4. Multiplicative homomorphism attack on raw RSA signatures
  5. EUF-CMA security game

Dependencies: crypto.rsa, crypto.dlp_crhf, crypto.utils
Used by: (CCA-PKC)
"""

from crypto.utils import mod_exp, random_bytes, bytes_to_int, int_to_bytes, to_hex
from crypto.rsa import rsa_keygen, RSAKeyPair
from crypto.dlp_crhf import DLP_CRHF, get_crhf


# ---------------------------------------------------------------------------
# Digital Signature Scheme (RSA + Hash)
# ---------------------------------------------------------------------------

class DigitalSignature:
    """
    RSA-based digital signature scheme.

    Sign: σ = H(m)^d mod N
    Verify: σ^e mod N == H(m)

    Uses Hash-then-Sign with the DLP-CRHF from .
    """

    def __init__(self, key_pair: RSAKeyPair = None, crhf: DLP_CRHF = None,
                 bits: int = 512):
        if key_pair is None:
            key_pair = rsa_keygen(bits)
        if crhf is None:
            crhf = DLP_CRHF(bits=min(64, bits // 8))
        self.kp = key_pair
        self.crhf = crhf

    def _hash_message(self, message: bytes) -> int:
        """Hash the message and convert to integer mod N."""
        h = self.crhf.hash(message)
        return bytes_to_int(h) % self.kp.n

    def sign(self, message: bytes) -> int:
        """
        Sign a message.

        Args:
            message: Arbitrary-length message.

        Returns:
            Signature σ (integer).
        """
        h = self._hash_message(message)
        sigma = mod_exp(h, self.kp.d, self.kp.n)
        return sigma

    def verify(self, message: bytes, sigma: int) -> bool:
        """
        Verify a signature.

        Args:
            message: Original message.
            sigma: Signature to verify.

        Returns:
            True if valid.
        """
        h = self._hash_message(message)
        recovered = mod_exp(sigma, self.kp.e, self.kp.n)
        return recovered == h

    def sign_raw(self, m_int: int) -> int:
        """Sign an integer directly (no hashing). For attack demos."""
        return mod_exp(m_int, self.kp.d, self.kp.n)

    def verify_raw(self, m_int: int, sigma: int) -> bool:
        """Verify a raw signature (no hashing). For attack demos."""
        return mod_exp(sigma, self.kp.e, self.kp.n) == m_int


# ---------------------------------------------------------------------------
# Multiplicative Homomorphism Attack
# ---------------------------------------------------------------------------

def homomorphism_attack_demo(bits: int = 256) -> dict:
    """
    Demonstrate multiplicative homomorphism attack on raw RSA signatures.

    Given σ₁ = m₁^d and σ₂ = m₂^d,
    compute σ₃ = σ₁ · σ₂ = (m₁ · m₂)^d = Sign(m₁ · m₂).

    This forges a valid signature on m₁·m₂ without knowing d.
    Hash-then-sign prevents this because H(m₁·m₂) ≠ H(m₁)·H(m₂).
    """
    ds = DigitalSignature(bits=bits)

    m1, m2 = 7, 11
    m3 = (m1 * m2) % ds.kp.n

    # Sign m1 and m2 (raw, no hash)
    sigma1 = ds.sign_raw(m1)
    sigma2 = ds.sign_raw(m2)

    # Forge signature on m3 = m1*m2
    sigma3_forged = (sigma1 * sigma2) % ds.kp.n

    # Verify
    raw_attack_works = ds.verify_raw(m3, sigma3_forged)

    # Now try with hash-then-sign
    sigma1_h = ds.sign(int_to_bytes(m1, 8))
    sigma2_h = ds.sign(int_to_bytes(m2, 8))
    sigma3_h_forged = (sigma1_h * sigma2_h) % ds.kp.n
    hash_attack_works = ds.verify(int_to_bytes(m3, 8), sigma3_h_forged)

    return {
        'm1': m1, 'm2': m2, 'm3': m3,
        'raw_attack_works': raw_attack_works,
        'hash_then_sign_attack_works': hash_attack_works,
        'conclusion': 'Raw RSA signatures are homomorphic → forgery possible. '
                      'Hash-then-sign breaks the homomorphism.',
    }


# ---------------------------------------------------------------------------
# EUF-CMA Game
# ---------------------------------------------------------------------------

def euf_cma_game(ds: DigitalSignature = None,
                  num_queries: int = 50,
                  num_attempts: int = 20) -> dict:
    """
    EUF-CMA game for digital signatures.

    Adversary gets signing oracle for num_queries messages,
    then tries to forge a signature on a new message.
    """
    if ds is None:
        ds = DigitalSignature(bits=256)

    # Phase 1: Signing oracle
    signed_messages = {}
    for _ in range(num_queries):
        m = random_bytes(16)
        sigma = ds.sign(m)
        signed_messages[m] = sigma

    # Phase 2: Forgery attempts
    successes = 0
    for _ in range(num_attempts):
        m_new = random_bytes(16)
        while m_new in signed_messages:
            m_new = random_bytes(16)

        # Try random signature
        from crypto.utils import random_int
        sigma_fake = random_int(2, ds.kp.n - 1)
        if ds.verify(m_new, sigma_fake):
            successes += 1

    return {
        'queries': num_queries,
        'forgery_attempts': num_attempts,
        'successful_forgeries': successes,
        'secure': successes == 0,
    }


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

def Sign(sk, message: bytes) -> int:
    """Sign a message. sk is a DigitalSignature instance."""
    return sk.sign(message)

def Verify(vk, message: bytes, sigma: int) -> bool:
    """Verify a signature. vk is a DigitalSignature instance."""
    return vk.verify(message, sigma)


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("Digital Signatures")
    print("=" * 60)

    ds = DigitalSignature(bits=512)

    # Sign and verify
    print("\n--- Sign/Verify ---")
    msg = b"Sign this important document!"
    sigma = ds.sign(msg)
    print(f"Message: {msg}")
    print(f"Signature: {sigma}")
    print(f"Verify: {ds.verify(msg, sigma)}")
    print(f"Wrong msg: {ds.verify(b'tampered', sigma)}")
    print(f"Wrong sig: {ds.verify(msg, sigma + 1)}")

    # Homomorphism attack
    print("\n--- Homomorphism Attack ---")
    attack = homomorphism_attack_demo(256)
    print(f"Raw RSA forgery works: {attack['raw_attack_works']}")
    print(f"Hash-then-sign forgery works: {attack['hash_then_sign_attack_works']}")
    print(f"{attack['conclusion']}")

    # EUF-CMA
    print("\n--- EUF-CMA Game ---")
    game = euf_cma_game(ds)
    print(f"Forgeries: {game['successful_forgeries']}/{game['forgery_attempts']}")
    print(f"Secure: {game['secure']}")
