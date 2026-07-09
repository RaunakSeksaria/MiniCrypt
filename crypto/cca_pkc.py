"""
crypto/cca_pkc.py — CCA-Secure Public-Key Cryptosystem

Implements:
  1. Signcrypt (Encrypt-then-Sign): CCA_PKC_Enc(pk_enc, sk_sign, m)
  2. Verify-then-Decrypt: CCA_PKC_Dec(sk_enc, vk_sign, CE, σ)
  3. IND-CCA2 game
  4. Contrast: malleability on plain ElGamal vs blocked on CCA-PKC

Dependencies: crypto.signatures, crypto.elgamal
Full lineage: → → →
              → → →
"""

from crypto.elgamal import ElGamalKey, elgamal_decrypt, elgamal_encrypt, elgamal_keygen
from crypto.signatures import DigitalSignature
from crypto.utils import int_to_bytes, random_int

# ---------------------------------------------------------------------------
# CCA-Secure PKC (Encrypt-then-Sign)
# ---------------------------------------------------------------------------

class CCA_PKC:
    """
    CCA-secure public-key cryptosystem using Encrypt-then-Sign.

    Encrypt:
      1. CE ← ElGamal.Enc(pk_enc, m)
      2. σ ← Sign(sk_sign, CE)
      3. Output (CE, σ)

    Decrypt:
      1. Verify(vk_sign, CE, σ) — reject if invalid
      2. Output ElGamal.Dec(sk_enc, CE)
    """

    def __init__(self, eg_key: ElGamalKey = None, sig: DigitalSignature = None,
                 eg_bits: int = 64, rsa_bits: int = 512):
        if eg_key is None:
            eg_key = elgamal_keygen(bits=eg_bits)
        if sig is None:
            sig = DigitalSignature(bits=rsa_bits)

        self.eg_key = eg_key
        self.sig = sig

    def encrypt(self, m: int) -> dict:
        """
        CCA-secure encryption.

        Args:
            m: Plaintext (group element, integer in [1, p-1]).

        Returns:
            dict with 'c1', 'c2', 'sigma'.
        """
        # Step 1: ElGamal encrypt
        c1, c2 = elgamal_encrypt(self.eg_key.pk, m)

        # Step 2: Sign the ciphertext
        ce_bytes = int_to_bytes(c1, (self.eg_key.p.bit_length() + 7) // 8)
        ce_bytes += int_to_bytes(c2, (self.eg_key.p.bit_length() + 7) // 8)
        sigma = self.sig.sign(ce_bytes)

        return {'c1': c1, 'c2': c2, 'sigma': sigma}

    def decrypt(self, c1: int, c2: int, sigma: int):
        """
        CCA-secure decryption.

        Returns:
            Plaintext m, or None (⊥) if signature is invalid.
        """
        # Step 1: Verify signature FIRST
        ce_bytes = int_to_bytes(c1, (self.eg_key.p.bit_length() + 7) // 8)
        ce_bytes += int_to_bytes(c2, (self.eg_key.p.bit_length() + 7) // 8)

        if not self.sig.verify(ce_bytes, sigma):
            return None  # ⊥ — signature invalid, decryption ABORTED

        # Step 2: Decrypt only if signature valid
        return elgamal_decrypt(self.eg_key.sk, self.eg_key.p, c1, c2)


# ---------------------------------------------------------------------------
# IND-CCA2 Game
# ---------------------------------------------------------------------------

def ind_cca2_game(cca: CCA_PKC = None, num_rounds: int = 50) -> dict:
    """
    IND-CCA2 game for CCA-PKC.

    Adversary has decryption oracle but cannot submit the challenge ciphertext.
    Modified ciphertexts should be rejected (signature fails).
    """
    import random

    if cca is None:
        cca = CCA_PKC(eg_bits=64, rsa_bits=256)

    correct = 0
    oracle_rejects = 0

    for _ in range(num_rounds):
        m0 = random_int(1, cca.eg_key.p - 2)
        m1 = random_int(1, cca.eg_key.p - 2)

        b = random.randint(0, 1)
        chosen = m0 if b == 0 else m1

        ct = cca.encrypt(chosen)

        # Adversary tries decryption oracle with modified ciphertext
        c2_modified = (ct['c2'] * 2) % cca.eg_key.p
        result = cca.decrypt(ct['c1'], c2_modified, ct['sigma'])
        if result is None:
            oracle_rejects += 1

        b_guess = random.randint(0, 1)
        if b_guess == b:
            correct += 1

    return {
        'rounds': num_rounds,
        'advantage': abs(correct / num_rounds - 0.5),
        'oracle_rejects': oracle_rejects,
        'secure': oracle_rejects == num_rounds,
    }


# ---------------------------------------------------------------------------
# Contrast: Plain ElGamal vs CCA-PKC
# ---------------------------------------------------------------------------

def contrast_demo(cca: CCA_PKC = None) -> dict:
    """
    Contrast plain ElGamal (malleable) vs CCA-PKC (not malleable).
    """
    if cca is None:
        cca = CCA_PKC(eg_bits=64, rsa_bits=256)

    m = random_int(1, cca.eg_key.p - 2)

    # --- Plain ElGamal (malleable) ---
    c1, c2 = elgamal_encrypt(cca.eg_key.pk, m)
    c2_tampered = (c2 * 2) % cca.eg_key.p
    m_tampered = elgamal_decrypt(cca.eg_key.sk, cca.eg_key.p, c1, c2_tampered)
    elgamal_malleable = m_tampered == (2 * m) % cca.eg_key.p

    # --- CCA-PKC (not malleable) ---
    ct = cca.encrypt(m)
    c2_cca_tampered = (ct['c2'] * 2) % cca.eg_key.p
    cca_result = cca.decrypt(ct['c1'], c2_cca_tampered, ct['sigma'])
    cca_rejected = cca_result is None

    # Untampered CCA decryption should work
    cca_clean = cca.decrypt(ct['c1'], ct['c2'], ct['sigma'])

    return {
        'original_m': m,
        'plain_elgamal': {
            'tampered_decrypts_to': m_tampered,
            'expected_2m': (2 * m) % cca.eg_key.p,
            'malleable': elgamal_malleable,
        },
        'cca_pkc': {
            'tampered_result': cca_result,
            'rejected': cca_rejected,
            'clean_decrypt': cca_clean,
            'clean_correct': cca_clean == m,
        },
    }


# ---------------------------------------------------------------------------
# Full Lineage Check
# ---------------------------------------------------------------------------

def lineage_trace() -> str:
    """Return the dependency chain as a string for the README."""
    return """
    (CCA-PKC)
    ├── (ElGamal) → encrypt/decrypt
    │   └── (Diffie-Hellman) → group parameters
    │       └── (Miller-Rabin) → safe prime generation
    └── (Digital Signatures) → sign/verify
        ├── (RSA) → signing key
        │   └── (Miller-Rabin) → prime generation
        └── (DLP-CRHF) → hash function for hash-then-sign
            ├── (Merkle-Damgård) → hash framework
            └── (Miller-Rabin) → DLP group setup
    """


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("CCA-Secure PKC (Encrypt-then-Sign)")
    print("=" * 60)

    cca = CCA_PKC(eg_bits=64, rsa_bits=256)

    # Basic encrypt/decrypt
    print("\n--- Encrypt/Decrypt ---")
    m = 42
    ct = cca.encrypt(m)
    pt = cca.decrypt(ct['c1'], ct['c2'], ct['sigma'])
    print(f"Enc({m}) → (c1={ct['c1']}, c2={ct['c2']}, σ={ct['sigma']})")
    print(f"Dec → {pt}")
    print(f"Match: {pt == m}")

    # Tampered → rejected
    ct2_bad = (ct['c2'] * 2) % cca.eg_key.p
    pt_bad = cca.decrypt(ct['c1'], ct2_bad, ct['sigma'])
    print(f"Tampered decrypt: {pt_bad} (should be None/⊥)")

    # Contrast
    print("\n--- Contrast: ElGamal vs CCA-PKC ---")
    contrast = contrast_demo(cca)
    print(f"Plain ElGamal malleable: {contrast['plain_elgamal']['malleable']}")
    print(f"CCA-PKC rejects tamper: {contrast['cca_pkc']['rejected']}")
    print(f"CCA-PKC clean decrypt: {contrast['cca_pkc']['clean_correct']}")

    # CCA2 game
    print("\n--- IND-CCA2 Game ---")
    game = ind_cca2_game(cca, num_rounds=50)
    print(f"Oracle rejects: {game['oracle_rejects']}/{game['rounds']}")
    print(f"Advantage: {game['advantage']:.4f}")

    # Lineage
    print("\n--- Full Lineage ---")
    print(lineage_trace())
