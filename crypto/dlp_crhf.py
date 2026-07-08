"""
crypto/dlp_crhf.py — DLP-Based Collision-Resistant Hash Function

Implements:
  1. Group setup: safe-prime subgroup with generators g, h = g^α (α discarded)
  2. DLP compression function: compress(x, y) = g^x · h^y mod p
  3. Full CRHF: plug into Merkle-Damgård framework
  4. Collision resistance demonstration

Dependencies: crypto.merkle_damgard, crypto.miller_rabin, crypto.utils
Used by: (birthday attack), (HMAC), (signatures)
"""

from crypto.utils import (
    mod_exp, random_int, random_bytes, bytes_to_int, int_to_bytes,
    to_hex, int_to_bytes_auto
)
from crypto.miller_rabin import gen_safe_prime, find_generator
from crypto.merkle_damgard import MerkleDamgard


# ---------------------------------------------------------------------------
# DLP Group Setup
# ---------------------------------------------------------------------------

class DLPGroup:
    """
    Group parameters for the DLP-based hash.
    Uses a safe-prime subgroup of Z*_p.
    """

    def __init__(self, bits: int = 64):
        """
        Generate group parameters.

        Args:
            bits: Bit length of the safe prime p.
        """
        self.p, self.q = gen_safe_prime(bits)
        self.g = find_generator(self.p, self.q)

        # Generate h = g^α for random α, then DISCARD α
        alpha = random_int(2, self.q - 1)
        self.h = mod_exp(self.g, alpha, self.p)
        # α is NOT stored — nobody knows log_g(h)

        self.bits = bits

    def __repr__(self):
        return f"DLPGroup(p={self.p}, q={self.q}, g={self.g}, h={self.h})"


# ---------------------------------------------------------------------------
# DLP Compression Function
# ---------------------------------------------------------------------------

class DLPCompress:
    """
    DLP-based compression function:
    compress(x, y) = g^x · h^y mod p

    Maps (Z_q × Z_q) → G.
    Collision resistance reduces to the DLP: finding (x,y) ≠ (x',y')
    with compress(x,y) = compress(x',y') would reveal log_g(h) = (x-x')/(y'-y) mod q.
    """

    def __init__(self, group: DLPGroup = None, bits: int = 64):
        if group is None:
            group = DLPGroup(bits)
        self.group = group
        self.p = group.p
        self.q = group.q
        self.g = group.g
        self.h = group.h

    def compress(self, x: int, y: int) -> int:
        """Compute h(x, y) = g^x · h^y mod p."""
        gx = mod_exp(self.g, x % self.q, self.p)
        hy = mod_exp(self.h, y % self.q, self.p)
        return (gx * hy) % self.p

    def compress_bytes(self, cv: bytes, block: bytes) -> bytes:
        """
        Compression function interface for Merkle-Damgård.
        cv = chaining value (interpreted as integer mod q)
        block = data block (interpreted as integer mod q)
        Returns: group element as bytes (fixed length).
        """
        x = bytes_to_int(cv) % self.q
        y = bytes_to_int(block) % self.q
        result = self.compress(x, y)
        return int_to_bytes(result, self.output_byte_length())

    def output_byte_length(self) -> int:
        """Number of bytes needed to represent a group element."""
        return (self.p.bit_length() + 7) // 8


# ---------------------------------------------------------------------------
# Full DLP CRHF (Merkle-Damgård + DLP Compression)
# ---------------------------------------------------------------------------

class DLP_CRHF:
    """
    Complete DLP-based collision-resistant hash function.
    Uses the DLP compression function plugged into Merkle-Damgård.
    """

    def __init__(self, bits: int = 64, group: DLPGroup = None):
        """
        Args:
            bits: Bit length for the safe prime (determines security).
        """
        self.dlp = DLPCompress(group, bits)
        self.digest_size = self.dlp.output_byte_length()

        # Block size: typically 2× the CV size (to get compression)
        self.block_size = self.digest_size

        # IV: hash of nothing — use 0
        iv = int_to_bytes(0, self.digest_size)

        # Create Merkle-Damgård instance
        self.md = MerkleDamgard(
            compress=self.dlp.compress_bytes,
            iv=iv,
            block_size=self.block_size,
        )

    def hash(self, message: bytes) -> bytes:
        """
        Hash an arbitrary-length message.

        Returns:
            Group element as bytes (digest_size bytes).
        """
        return self.md.hash(message)

    def hash_int(self, message: bytes) -> int:
        """Hash and return the result as an integer."""
        return bytes_to_int(self.hash(message))

    def hash_truncated(self, message: bytes, output_bits: int) -> int:
        """
        Hash and truncate to the specified number of output bits.
        Used for birthday attack demos with small output sizes.
        """
        full_hash = self.hash_int(message)
        mask = (1 << output_bits) - 1
        return full_hash & mask

    def hash_with_trace(self, message: bytes) -> dict:
        """Hash with intermediate values for visualization."""
        return self.md.hash_with_trace(message)


# ---------------------------------------------------------------------------
# Collision Resistance Demo
# ---------------------------------------------------------------------------

def collision_resistance_demo(bits: int = 32) -> dict:
    """
    Demonstrate collision resistance of the DLP hash.
    Show that finding a collision would require solving DLP.
    """
    crhf = DLP_CRHF(bits=bits)

    # Hash several distinct messages — all outputs should differ
    messages = [b"Hello", b"World", b"Test", b"Hash", b"DLP!"]
    hashes = {}
    collisions = []

    for msg in messages:
        h = crhf.hash(msg)
        h_hex = to_hex(h)
        if h_hex in hashes:
            collisions.append((hashes[h_hex], msg))
        hashes[h_hex] = msg

    return {
        'group_bits': bits,
        'p': crhf.dlp.p,
        'num_messages': len(messages),
        'distinct_hashes': len(set(hashes.keys())),
        'collisions_found': len(collisions),
        'all_distinct': len(collisions) == 0,
        'security_claim': f'Finding collision requires O(sqrt(q)) ≈ O(2^{bits//2}) work (birthday bound)',
    }


def brute_force_collision_demo(output_bits: int = 16) -> dict:
    """
    Brute-force collision finder for tiny parameters.
    Shows the birthday bound empirically.
    """
    crhf = DLP_CRHF(bits=32)  # Small group for speed

    seen = {}
    evaluations = 0

    while True:
        msg = random_bytes(8)
        h = crhf.hash_truncated(msg, output_bits)
        evaluations += 1

        if h in seen and seen[h] != msg:
            return {
                'output_bits': output_bits,
                'evaluations': evaluations,
                'expected_birthday': 2 ** (output_bits / 2),
                'ratio': evaluations / (2 ** (output_bits / 2)),
                'collision': {
                    'msg1': to_hex(seen[h]),
                    'msg2': to_hex(msg),
                    'hash': h,
                },
            }
        seen[h] = msg

        if evaluations > 2 ** (output_bits + 2):
            return {'output_bits': output_bits, 'evaluations': evaluations,
                    'found': False}


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

_default_crhf = None

def DLP_Hash(message: bytes, bits: int = 64) -> bytes:
    """
    Convenience function: hash using DLP-CRHF.
    Creates a shared instance on first use.
    """
    global _default_crhf
    if _default_crhf is None:
        _default_crhf = DLP_CRHF(bits=bits)
    return _default_crhf.hash(message)


def get_crhf(bits: int = 64) -> DLP_CRHF:
    """Get or create a DLP-CRHF instance."""
    global _default_crhf
    if _default_crhf is None:
        _default_crhf = DLP_CRHF(bits=bits)
    return _default_crhf


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("DLP-Based Collision-Resistant Hash Function")
    print("=" * 60)

    # Create CRHF with small parameters
    print("\n--- DLP Group Setup ---")
    crhf = DLP_CRHF(bits=32)
    print(f"p = {crhf.dlp.p}")
    print(f"q = {crhf.dlp.q}")
    print(f"g = {crhf.dlp.g}")
    print(f"h = {crhf.dlp.h}")
    print(f"Digest size: {crhf.digest_size} bytes")

    # Hash some messages
    print("\n--- Hash Outputs ---")
    for msg in [b"Hello!", b"Hello!!", b"Test", b"", b"Longer message for hashing"]:
        h = crhf.hash(msg)
        print(f"H({msg[:20]!r}) = {to_hex(h)}")

    # Collision resistance
    print("\n--- Collision Resistance Demo ---")
    demo = collision_resistance_demo(bits=32)
    print(f"All {demo['num_messages']} hashes distinct: {demo['all_distinct']}")
    print(f"{demo['security_claim']}")

    # Birthday attack on truncated hash
    print("\n--- Birthday Attack (truncated to 16 bits) ---")
    bd = brute_force_collision_demo(output_bits=16)
    if 'collision' in bd:
        print(f"Collision found after {bd['evaluations']} evaluations")
        print(f"Expected (birthday): {bd['expected_birthday']:.0f}")
        print(f"Ratio: {bd['ratio']:.2f}")
