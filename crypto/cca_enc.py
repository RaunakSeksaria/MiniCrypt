"""
crypto/cca_enc.py — CCA-Secure Symmetric Encryption

Implements:
  1. Encrypt-then-MAC: CCA_Enc(kE, kM, m) → (c, t)
  2. CCA_Dec(kE, kM, c, t) → m or ⊥ (MAC-first verification)
  3. IND-CCA2 game simulation
  4. Malleability attack demo (CPA-only vs CCA)

Dependencies: crypto.cpa_enc (CPA-Enc), crypto.mac (MAC)
"""

from crypto.aes import BLOCK_SIZE
from crypto.cpa_enc import CPAEncryption
from crypto.mac import MAC
from crypto.utils import random_bytes, random_int, to_hex

# ---------------------------------------------------------------------------
# CCA-Secure Encryption (Encrypt-then-MAC)
# ---------------------------------------------------------------------------

class CCAEncryption:
    """
    CCA-secure symmetric encryption using Encrypt-then-MAC paradigm.

    Encryption: CE ← Enc_{kE}(m), t ← Mac_{kM}(CE), output (CE, t)
    Decryption: Verify Mac_{kM}(CE) == t first; if not, return ⊥; else Dec_{kE}(CE)

    Uses independent keys kE (encryption) and kM (MAC).
    """

    def __init__(self, enc: CPAEncryption = None, mac: MAC = None):
        if enc is None:
            enc = CPAEncryption()
        if mac is None:
            mac = MAC(mode='cbc')
        self.enc = enc
        self.mac = mac
        self.block_size = BLOCK_SIZE

    def encrypt(self, key_enc: bytes, key_mac: bytes,
                plaintext: bytes) -> tuple:
        """
        CCA-secure encryption.

        Args:
            key_enc: Encryption key (16 bytes).
            key_mac: MAC key (16 bytes, MUST differ from key_enc).
            plaintext: Message of arbitrary length.

        Returns:
            (r, ciphertext, tag) — nonce, encrypted message, MAC tag.
        """
        # Step 1: CPA-secure encrypt
        r, ct = self.enc.encrypt(key_enc, plaintext)

        # Step 2: MAC the ciphertext (including nonce r for binding)
        mac_input = r + ct  # MAC covers both nonce and ciphertext
        tag = self.mac.Mac(key_mac, mac_input)

        return r, ct, tag

    def decrypt(self, key_enc: bytes, key_mac: bytes,
                r: bytes, ciphertext: bytes, tag: bytes):
        """
        CCA-secure decryption.

        Returns:
            Original plaintext, or None (⊥) if MAC verification fails.
        """
        # Step 1: Verify MAC FIRST (before any decryption)
        mac_input = r + ciphertext
        if not self.mac.Vrfy(key_mac, mac_input, tag):
            return None  # ⊥ — reject tampered ciphertext

        # Step 2: Decrypt only if MAC is valid
        return self.enc.decrypt(key_enc, r, ciphertext)


# ---------------------------------------------------------------------------
# IND-CCA2 Game
# ---------------------------------------------------------------------------

def ind_cca2_game(num_rounds: int = 50) -> dict:
    """
    Simulate the IND-CCA2 game.

    The adversary has access to:
      - Encryption oracle
      - Decryption oracle (rejects the challenge ciphertext)

    A secure CCA scheme should have advantage ≈ 0.
    """

    cca = CCAEncryption()
    key_enc = random_bytes(BLOCK_SIZE)
    key_mac = random_bytes(BLOCK_SIZE)

    correct = 0
    oracle_rejects = 0

    for _ in range(num_rounds):
        # Adversary picks two messages
        msg_len = random_int(1, 32)
        m0 = random_bytes(msg_len)
        m1 = random_bytes(msg_len)

        # Challenger encrypts m_b
        b = random_int(0, 1)
        chosen = m0 if b == 0 else m1
        r_star, ct_star, tag_star = cca.encrypt(key_enc, key_mac, chosen)

        # Adversary tries to use decryption oracle with modified ciphertext
        ct_modified = bytearray(ct_star)
        ct_modified[0] ^= 0x01  # Flip one bit
        result = cca.decrypt(key_enc, key_mac, r_star, bytes(ct_modified), tag_star)
        if result is None:
            oracle_rejects += 1  # Good — CCA properly rejects

        # Adversary guesses randomly
        b_guess = random_int(0, 1)
        if b_guess == b:
            correct += 1

    advantage = abs(correct / num_rounds - 0.5)
    return {
        'rounds': num_rounds,
        'correct_guesses': correct,
        'win_rate': correct / num_rounds,
        'advantage': advantage,
        'oracle_rejects': oracle_rejects,
        'total_oracle_queries': num_rounds,
        'secure': advantage < 0.15,
    }


# ---------------------------------------------------------------------------
# Malleability Attack Demo
# ---------------------------------------------------------------------------

def malleability_attack_demo() -> dict:
    """
    Demonstrate that CPA-only encryption is malleable but CCA is not.

    CPA attack: flip bit i of ciphertext → flips bit i of plaintext.
    CCA defense: MAC check detects the modification → returns ⊥.
    """
    enc_obj = CPAEncryption()
    cca_obj = CCAEncryption()

    key_enc = random_bytes(BLOCK_SIZE)
    key_mac = random_bytes(BLOCK_SIZE)

    message = b"Transfer $1000!!"  # 16 bytes

    # --- CPA-only: malleable ---
    r, ct = enc_obj.encrypt(key_enc, message)
    ct_flipped = bytearray(ct)
    ct_flipped[0] ^= 0x01  # Flip first bit
    pt_flipped = enc_obj.decrypt(key_enc, r, bytes(ct_flipped))

    # --- CCA: not malleable ---
    r2, ct2, tag2 = cca_obj.encrypt(key_enc, key_mac, message)
    ct2_flipped = bytearray(ct2)
    ct2_flipped[0] ^= 0x01
    cca_result = cca_obj.decrypt(key_enc, key_mac, r2, bytes(ct2_flipped), tag2)

    return {
        'original_message': message,
        'cpa_only': {
            'original_ct': to_hex(ct),
            'flipped_ct': to_hex(bytes(ct_flipped)),
            'decrypted': pt_flipped,
            'malleable': pt_flipped != message and pt_flipped is not None,
        },
        'cca_secure': {
            'original_ct': to_hex(ct2),
            'flipped_ct': to_hex(bytes(ct2_flipped)),
            'decrypted': cca_result,
            'rejected': cca_result is None,
        },
    }


# ---------------------------------------------------------------------------
# Key Separation Demo
# ---------------------------------------------------------------------------

def key_separation_demo() -> dict:
    """
    Demonstrate that independent keys are required.
    Show that using the same key for both Enc and MAC is dangerous.
    """
    cca = CCAEncryption()
    shared_key = random_bytes(BLOCK_SIZE)
    independent_key_enc = random_bytes(BLOCK_SIZE)
    independent_key_mac = random_bytes(BLOCK_SIZE)

    message = b"Test key separation"

    # With shared key (potentially insecure)
    r1, ct1, tag1 = cca.encrypt(shared_key, shared_key, message)
    pt1 = cca.decrypt(shared_key, shared_key, r1, ct1, tag1)

    # With independent keys (recommended)
    r2, ct2, tag2 = cca.encrypt(independent_key_enc, independent_key_mac, message)
    pt2 = cca.decrypt(independent_key_enc, independent_key_mac, r2, ct2, tag2)

    return {
        'shared_key_works': pt1 == message,
        'independent_keys_work': pt2 == message,
        'warning': 'Using the same key for encryption and MAC creates '
                   'exploitable correlations. Always use independent keys.',
    }


# ---------------------------------------------------------------------------
# Interface functions
# ---------------------------------------------------------------------------

_default_cca = None

def _get_default():
    global _default_cca
    if _default_cca is None:
        _default_cca = CCAEncryption()
    return _default_cca

def CCA_Enc(key_enc: bytes, key_mac: bytes, plaintext: bytes) -> tuple:
    """CCA-secure encrypt: returns (r, ciphertext, tag)."""
    return _get_default().encrypt(key_enc, key_mac, plaintext)

def CCA_Dec(key_enc: bytes, key_mac: bytes, r: bytes,
            ciphertext: bytes, tag: bytes):
    """CCA-secure decrypt: returns plaintext or None (⊥)."""
    return _get_default().decrypt(key_enc, key_mac, r, ciphertext, tag)


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("CCA-Secure Symmetric Encryption")
    print("=" * 60)

    cca = CCAEncryption()
    ke = random_bytes(BLOCK_SIZE)
    km = random_bytes(BLOCK_SIZE)

    # Basic encrypt/decrypt
    print("\n--- Encrypt-then-MAC ---")
    msg = b"Confidential and authenticated message!"
    r, ct, tag = cca.encrypt(ke, km, msg)
    pt = cca.decrypt(ke, km, r, ct, tag)
    print(f"Original:  {msg}")
    print(f"Decrypted: {pt}")
    print(f"Match: {pt == msg}")

    # Tampered ciphertext → ⊥
    ct_bad = bytearray(ct)
    ct_bad[0] ^= 0xFF
    pt_bad = cca.decrypt(ke, km, r, bytes(ct_bad), tag)
    print(f"Tampered decrypt: {pt_bad} (should be None/⊥)")

    # IND-CCA2 game
    print("\n--- IND-CCA2 Game ---")
    game = ind_cca2_game(num_rounds=100)
    print(f"Win rate: {game['win_rate']:.2f} (should be ~0.50)")
    print(f"Advantage: {game['advantage']:.4f}")
    print(f"Oracle rejects: {game['oracle_rejects']}/{game['total_oracle_queries']}")

    # Malleability attack
    print("\n--- Malleability Attack Demo ---")
    attack = malleability_attack_demo()
    print(f"CPA-only malleable: {attack['cpa_only']['malleable']}")
    print(f"CCA rejected tamper: {attack['cca_secure']['rejected']}")
