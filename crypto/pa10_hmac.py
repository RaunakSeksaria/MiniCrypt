"""
crypto/pa10_hmac.py — PA#10: HMAC and HMAC-Based CCA-Secure Encryption

Implements:
  1. HMAC using PA#8 DLP Hash: H((k⊕opad) ‖ H((k⊕ipad) ‖ m))
  2. HMAC_Verify with constant-time comparison
  3. CRHF ⇒ MAC (EUF-CMA game on HMAC)
  4. MAC ⇒ CRHF (HMAC as compression function in Merkle-Damgård)
  5. Length-extension attack demo
  6. Encrypt-then-HMAC (CCA-secure encryption)
  7. Constant-time comparison with timing demo

Dependencies: crypto.pa08_dlp_crhf, crypto.pa07_merkle_damgard, crypto.pa03_cpa_enc
Bidirectional: CRHF ⇔ MAC via HMAC
"""

import time
from crypto.utils import (
    xor_bytes, random_bytes, bytes_to_int, int_to_bytes, to_hex
)
from crypto.pa07_merkle_damgard import MerkleDamgard
from crypto.pa08_dlp_crhf import DLP_CRHF, get_crhf
from crypto.pa03_cpa_enc import CPAEncryption
from crypto.aes import BLOCK_SIZE


# ---------------------------------------------------------------------------
# HMAC Implementation
# ---------------------------------------------------------------------------

class HMAC:
    """
    HMAC construction using the DLP hash from PA#8.

    HMAC_k(m) = H((k ⊕ opad) ‖ H((k ⊕ ipad) ‖ m))

    where:
      ipad = 0x36 repeated to block_size bytes
      opad = 0x5C repeated to block_size bytes
    """

    def __init__(self, crhf: DLP_CRHF = None, bits: int = 64):
        """
        Args:
            crhf: DLP-CRHF instance. If None, creates one.
            bits: Bit size for group parameters.
        """
        if crhf is None:
            crhf = DLP_CRHF(bits=bits)
        self.crhf = crhf
        self.block_size = crhf.block_size
        self.digest_size = crhf.digest_size

        # HMAC constants
        self.ipad = bytes([0x36] * self.block_size)
        self.opad = bytes([0x5C] * self.block_size)

    def _prepare_key(self, key: bytes) -> bytes:
        """
        Prepare key for HMAC:
        - If |k| > block_size: hash it first
        - If |k| < block_size: zero-pad to block_size
        """
        if len(key) > self.block_size:
            key = self.crhf.hash(key)
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
        return key

    def mac(self, key: bytes, message: bytes) -> bytes:
        """
        Compute HMAC_k(m).

        HMAC_k(m) = H((k ⊕ opad) ‖ H((k ⊕ ipad) ‖ m))
        """
        k = self._prepare_key(key)

        # Inner hash: H((k ⊕ ipad) ‖ m)
        inner_key = xor_bytes(k, self.ipad)
        inner_data = inner_key + message
        inner_hash = self.crhf.hash(inner_data)

        # Outer hash: H((k ⊕ opad) ‖ inner_hash)
        outer_key = xor_bytes(k, self.opad)
        outer_data = outer_key + inner_hash
        outer_hash = self.crhf.hash(outer_data)

        return outer_hash

    def verify(self, key: bytes, message: bytes, tag: bytes) -> bool:
        """
        Verify HMAC tag using constant-time comparison.
        """
        expected = self.mac(key, message)
        return secure_compare(expected, tag)


# ---------------------------------------------------------------------------
# Constant-Time Comparison
# ---------------------------------------------------------------------------

def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    XOR all bytes and check result is zero.
    Prevents timing side-channel attacks.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def naive_compare(a: bytes, b: bytes) -> bool:
    """
    INSECURE naive comparison (early-exit).
    Used to demonstrate timing side-channel vulnerability.
    """
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


def timing_attack_demo() -> dict:
    """
    Demonstrate timing side-channel in naive comparison.
    Tags differing in early bytes return faster than those differing in late bytes.
    """
    tag = random_bytes(16)
    results = {'early_diff': [], 'late_diff': [], 'correct': []}

    for _ in range(100):
        # Tag differing at byte 0
        early = bytearray(tag)
        early[0] ^= 0xFF
        start = time.perf_counter_ns()
        naive_compare(tag, bytes(early))
        results['early_diff'].append(time.perf_counter_ns() - start)

        # Tag differing at last byte
        late = bytearray(tag)
        late[-1] ^= 0xFF
        start = time.perf_counter_ns()
        naive_compare(tag, bytes(late))
        results['late_diff'].append(time.perf_counter_ns() - start)

        # Correct tag
        start = time.perf_counter_ns()
        naive_compare(tag, tag)
        results['correct'].append(time.perf_counter_ns() - start)

    avg_early = sum(results['early_diff']) / len(results['early_diff'])
    avg_late = sum(results['late_diff']) / len(results['late_diff'])
    avg_correct = sum(results['correct']) / len(results['correct'])

    return {
        'avg_early_diff_ns': avg_early,
        'avg_late_diff_ns': avg_late,
        'avg_correct_ns': avg_correct,
        'timing_leak': avg_late > avg_early * 1.1,
        'note': 'Late-differing tags take longer → timing leak in naive comparison',
    }


# ---------------------------------------------------------------------------
# Length-Extension Attack Demo
# ---------------------------------------------------------------------------

def length_extension_attack(crhf, naive_tag: bytes, message: bytes, suffix: bytes) -> bytes:
    """
    Real Merkle-Damgård length-extension attack.

    Given: t = H(k ‖ m) = naive_tag  (attacker sees this)
    Goal:  forge H(k ‖ m ‖ pad(k‖m) ‖ suffix)  WITHOUT knowing k.

    Trick: naive_tag IS the final chaining value of H(k‖m).
    We create a new MerkleDamgard instance with IV = naive_tag
    and hash just `suffix`. The result equals H(k‖m‖pad(k‖m)‖suffix).
    """
    from crypto.pa07_merkle_damgard import MerkleDamgard
    forged_md = MerkleDamgard(
        compress=crhf.dlp.compress_bytes,
        iv=naive_tag,          # <- attacker injects the leaked state
        block_size=crhf.block_size,
    )
    return forged_md.hash(suffix)


def length_extension_demo(hmac_obj: HMAC = None, suffix: bytes = None) -> dict:
    """
    Demonstrate length-extension attack on naive H(k‖m) vs HMAC.

    Naive MAC: t = H(k ‖ m) — broken by length extension.
    HMAC: t = H((k⊕opad) ‖ H((k⊕ipad) ‖ m)) — secure.
    """
    if hmac_obj is None:
        hmac_obj = HMAC(bits=32)
    if suffix is None:
        suffix = b"evil suffix"

    key = random_bytes(hmac_obj.block_size)
    message = b"original message"

    # Naive H(k‖m) — the attacker sees (message, tag)
    naive_tag = hmac_obj.crhf.hash(key + message)

    # MD padding that was applied to (k ‖ m)
    padded_km = hmac_obj.crhf.md.pad(key + message)
    # The full extended message (attacker constructs this without k)
    # = original_message ‖ padding_of_(k‖m)[len(key):] ‖ suffix
    pad_suffix = padded_km[len(key) + len(message):]   # padding bytes only
    forged_message = message + pad_suffix + suffix      # what attacker claims

    # Forged tag — attacker computes this WITHOUT k
    forged_tag = length_extension_attack(hmac_obj.crhf, naive_tag, message, suffix)

    # Verify: server recomputes H(k ‖ forged_message) and checks == forged_tag
    server_check = hmac_obj.crhf.hash(key + forged_message)
    forgery_valid = (server_check == forged_tag)

    # HMAC is not vulnerable
    hmac_tag = hmac_obj.mac(key, message)
    # Attacker tries same trick with HMAC
    hmac_forged_attempt = length_extension_attack(hmac_obj.crhf, bytes.fromhex(to_hex(hmac_tag)), message, suffix)
    hmac_forgery_valid = hmac_obj.verify(key, forged_message, hmac_forged_attempt)

    return {
        'key_hex': to_hex(key),
        'message': message.decode(),
        'suffix': suffix.decode(errors='replace'),
        'forged_message': forged_message.decode(errors='replace'),
        'pad_suffix_hex': to_hex(pad_suffix),
        'naive_tag': to_hex(naive_tag),
        'forged_tag': to_hex(forged_tag),
        'forgery_valid': forgery_valid,
        'naive_vulnerable': forgery_valid,
        'hmac_tag': to_hex(hmac_tag),
        'hmac_forgery_valid': hmac_forgery_valid,
        'hmac_secure': not hmac_forgery_valid,
        'explanation': (
            'Naive H(k‖m): the tag IS the final chaining value — attacker sets it as '
            'IV and continues hashing suffix → valid forgery. '
            'HMAC: outer hash wraps the inner result, so the chaining value is never exposed.'
        ),
    }


# ---------------------------------------------------------------------------
# Encrypt-then-HMAC (CCA-secure encryption)
# ---------------------------------------------------------------------------

class EncryptThenHMAC:
    """
    CCA-secure encryption using Encrypt-then-HMAC.

    Enc: C = Enc_{kE}(m), t = HMAC_{kM}(C), output (C, t)
    Dec: verify HMAC first, then decrypt. Return ⊥ on failure.
    """

    def __init__(self, cpa_enc: CPAEncryption = None, hmac: HMAC = None):
        if cpa_enc is None:
            cpa_enc = CPAEncryption()
        if hmac is None:
            hmac = HMAC(bits=32)
        self.enc = cpa_enc
        self.hmac = hmac

    def encrypt(self, key_enc: bytes, key_mac: bytes,
                plaintext: bytes) -> tuple:
        """Encrypt-then-HMAC."""
        r, ct = self.enc.encrypt(key_enc, plaintext)
        tag = self.hmac.mac(key_mac, r + ct)
        return r, ct, tag

    def decrypt(self, key_enc: bytes, key_mac: bytes,
                r: bytes, ciphertext: bytes, tag: bytes):
        """Verify-then-decrypt. Returns plaintext or None."""
        if not self.hmac.verify(key_mac, r + ciphertext, tag):
            return None
        return self.enc.decrypt(key_enc, r, ciphertext)


# ---------------------------------------------------------------------------
# CRHF ⇒ MAC (forward direction)
# ---------------------------------------------------------------------------

def crhf_to_mac_demo(hmac_obj: HMAC = None, num_queries: int = 50) -> dict:
    """
    Demonstrate CRHF ⇒ MAC: HMAC is EUF-CMA secure.
    Run EUF-CMA game — adversary sees 50 tagged messages, tries to forge.
    """
    if hmac_obj is None:
        hmac_obj = HMAC(bits=32)

    key = random_bytes(hmac_obj.block_size)
    signed = {}

    for _ in range(num_queries):
        m = random_bytes(16)
        t = hmac_obj.mac(key, m)
        signed[m] = t

    # Forgery attempts
    successes = 0
    for _ in range(20):
        m_new = random_bytes(16)
        while m_new in signed:
            m_new = random_bytes(16)
        t_fake = random_bytes(hmac_obj.digest_size)
        if hmac_obj.verify(key, m_new, t_fake):
            successes += 1

    return {
        'queries': num_queries,
        'forgery_attempts': 20,
        'successes': successes,
        'secure': successes == 0,
    }


# ---------------------------------------------------------------------------
# MAC ⇒ CRHF (backward direction)
# ---------------------------------------------------------------------------

def mac_to_crhf_demo(hmac_obj: HMAC = None) -> dict:
    """
    Demonstrate MAC ⇒ CRHF: use HMAC as compression function in Merkle-Damgård.
    h'(cv, block) = HMAC_k(cv ‖ block) for a fixed public key k.
    """
    if hmac_obj is None:
        hmac_obj = HMAC(bits=32)

    fixed_key = random_bytes(hmac_obj.block_size)

    def hmac_compress(cv: bytes, block: bytes) -> bytes:
        """Use HMAC as a compression function."""
        return hmac_obj.mac(fixed_key, cv + block)

    md = MerkleDamgard(
        compress=hmac_compress,
        iv=b'\x00' * hmac_obj.digest_size,
        block_size=hmac_obj.block_size,
    )

    # Hash some messages
    hashes = {}
    messages = [b"msg1", b"msg2", b"msg3", b"msg4", b"msg5"]
    for m in messages:
        h = md.hash(m)
        hashes[to_hex(h)] = m

    return {
        'distinct_hashes': len(hashes),
        'total_messages': len(messages),
        'all_distinct': len(hashes) == len(messages),
        'conclusion': 'HMAC as compression → collision-resistant hash (MAC ⇒ CRHF)',
    }


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

_default_hmac = None
_default_eth = None

def get_hmac(bits: int = 32) -> HMAC:
    global _default_hmac
    if _default_hmac is None:
        _default_hmac = HMAC(bits=bits)
    return _default_hmac

def HMAC_tag(key: bytes, message: bytes) -> bytes:
    """Compute HMAC_k(m) -> tag bytes."""
    return get_hmac().mac(key, message)

def HMAC_Verify(key: bytes, message: bytes, tag: bytes) -> bool:
    """Verify HMAC tag using constant-time comparison."""
    return get_hmac().verify(key, message, tag)

def EtH_Enc(key_enc: bytes, key_mac: bytes, plaintext: bytes) -> tuple:
    """Encrypt-then-HMAC: returns (r, ciphertext, tag)."""
    global _default_eth
    if _default_eth is None:
        _default_eth = EncryptThenHMAC(hmac=get_hmac())
    return _default_eth.encrypt(key_enc, key_mac, plaintext)

def EtH_Dec(key_enc: bytes, key_mac: bytes, r: bytes, ciphertext: bytes, tag: bytes):
    """Verify-then-decrypt. Returns plaintext bytes or None (⊥) on failure."""
    global _default_eth
    if _default_eth is None:
        _default_eth = EncryptThenHMAC(hmac=get_hmac())
    return _default_eth.decrypt(key_enc, key_mac, r, ciphertext, tag)


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("PA#10: HMAC and HMAC-Based CCA-Secure Encryption")
    print("=" * 60)

    hmac = HMAC(bits=32)
    key = random_bytes(hmac.block_size)

    # Basic HMAC
    print("\n--- HMAC ---")
    msg = b"Authenticate this message"
    tag = hmac.mac(key, msg)
    print(f"HMAC({msg!r}) = {to_hex(tag)}")
    print(f"Verify: {hmac.verify(key, msg, tag)}")
    print(f"Tamper: {hmac.verify(key, msg, random_bytes(hmac.digest_size))}")

    # EUF-CMA
    print("\n--- CRHF ⇒ MAC (EUF-CMA) ---")
    euf = crhf_to_mac_demo(hmac)
    print(f"Forgeries: {euf['successes']}/20 (should be 0)")

    # MAC ⇒ CRHF
    print("\n--- MAC ⇒ CRHF ---")
    rev = mac_to_crhf_demo(hmac)
    print(f"Distinct hashes: {rev['distinct_hashes']}/{rev['total_messages']}")
    print(f"{rev['conclusion']}")

    # Length-extension
    print("\n--- Length-Extension Demo ---")
    le = length_extension_demo(hmac)
    print(f"Naive H(k‖m) vulnerable: {le['naive_vulnerable']}")
    print(f"HMAC secure: {le['hmac_secure']}")

    # Encrypt-then-HMAC
    print("\n--- Encrypt-then-HMAC ---")
    eth = EncryptThenHMAC(hmac=hmac)
    ke = random_bytes(BLOCK_SIZE)
    km = random_bytes(hmac.block_size)
    msg = b"Secret and authenticated!"
    r, ct, tag = eth.encrypt(ke, km, msg)
    pt = eth.decrypt(ke, km, r, ct, tag)
    print(f"Decrypt: {pt == msg}")
    ct_bad = bytearray(ct); ct_bad[0] ^= 1
    print(f"Tamper rejected: {eth.decrypt(ke, km, r, bytes(ct_bad), tag) is None}")

    # Timing
    print("\n--- Constant-Time Comparison ---")
    timing = timing_attack_demo()
    print(f"Naive early-diff avg: {timing['avg_early_diff_ns']:.0f} ns")
    print(f"Naive late-diff avg:  {timing['avg_late_diff_ns']:.0f} ns")
    print(f"Timing leak detected: {timing['timing_leak']}")
