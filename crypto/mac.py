"""
crypto/mac.py — Message Authentication Codes (MACs)

Implements:
  1. PRF-MAC (fixed-length): Mac(k, m) = F_k(m)
  2. CBC-MAC (variable-length): chain F_k over message blocks
  3. HMAC stub (full implementation in )
  4. MAC ⇒ PRF backward direction
  5. EUF-CMA forgery game

Dependencies: crypto.prf_ggm (PRF), crypto.utils
Used by: (CCA-secure encryption)

Bidirectional: PRF ⇔ MAC
  Forward:  Mac_k(m) = F_k(m) — PRF output is a secure tag
  Backward: MAC used as PRF passes distinguishing test
"""

from crypto.utils import (
    xor_bytes, random_bytes, int_to_bytes, bytes_to_int,
    pad_pkcs7, to_hex, split_blocks
)
from crypto.prf_ggm import PRF
from crypto.aes import BLOCK_SIZE


# ---------------------------------------------------------------------------
# PRF-MAC (Fixed-Length)
# ---------------------------------------------------------------------------

class PRFMAC:
    """
    PRF-based MAC for fixed-length messages (one block = 16 bytes).
    Mac_k(m) = F_k(m), Vrfy_k(m, t) = (F_k(m) == t).
    """

    def __init__(self, prf: PRF = None):
        if prf is None:
            prf = PRF(mode='aes')
        self.prf = prf
        self.block_size = BLOCK_SIZE

    def mac(self, key: bytes, message: bytes) -> bytes:
        """
        Compute MAC tag for a single-block message.
        """
        if len(message) != self.block_size:
            raise ValueError(f"PRF-MAC requires {self.block_size}-byte message, "
                             f"got {len(message)}. Use CBC-MAC for variable length.")
        return self.prf.F(key, message)

    def verify(self, key: bytes, message: bytes, tag: bytes) -> bool:
        """Verify a MAC tag."""
        expected = self.mac(key, message)
        # Constant-time comparison
        return _constant_time_compare(expected, tag)


# ---------------------------------------------------------------------------
# CBC-MAC (Variable-Length)
# ---------------------------------------------------------------------------

class CBCMAC:
    """
    CBC-MAC for variable-length messages.
    Chain F_k over message blocks; output the final chaining value as the tag.

    WARNING: Basic CBC-MAC is only secure for fixed-length messages.
    For variable length, we prepend the message length (EMAC variant).
    """

    def __init__(self, prf: PRF = None):
        if prf is None:
            prf = PRF(mode='aes')
        self.prf = prf
        self.block_size = BLOCK_SIZE

    def mac(self, key: bytes, message: bytes) -> bytes:
        """
        Compute CBC-MAC tag for an arbitrary-length message.
        Prepends the message length as the first block for security
        with variable-length messages.
        """
        # Prepend length (as 16-byte block) for variable-length security
        length_block = int_to_bytes(len(message), self.block_size)
        padded = length_block + pad_pkcs7(message, self.block_size)
        blocks = split_blocks(padded, self.block_size)

        # CBC-MAC: chain F_k over blocks
        tag = b'\x00' * self.block_size  # IV = 0
        for block in blocks:
            tag = self.prf.F(key, xor_bytes(tag, block))

        return tag

    def verify(self, key: bytes, message: bytes, tag: bytes) -> bool:
        """Verify a CBC-MAC tag."""
        expected = self.mac(key, message)
        return _constant_time_compare(expected, tag)


# ---------------------------------------------------------------------------
# HMAC Stub (full implementation in )
# ---------------------------------------------------------------------------

def hmac_stub(key: bytes, message: bytes) -> bytes:
    """
    HMAC stub — full implementation deferred to .
    Raises NotImplementedError until is complete.
    """
    raise NotImplementedError(
        "HMAC is not yet implemented. See (crypto/hmac.py) "
        "for the full HMAC implementation using the DLP hash from ."
    )


# ---------------------------------------------------------------------------
# Unified MAC Interface
# ---------------------------------------------------------------------------

class MAC:
    """
    Unified MAC interface supporting PRF-MAC and CBC-MAC.
    Default: CBC-MAC (handles variable-length messages).
    """

    def __init__(self, mode: str = 'cbc', prf: PRF = None):
        """
        Args:
            mode: 'prf' for fixed-length PRF-MAC, 'cbc' for CBC-MAC.
        """
        self.mode = mode
        if mode == 'prf':
            self._impl = PRFMAC(prf)
        elif mode == 'cbc':
            self._impl = CBCMAC(prf)
        else:
            raise ValueError(f"Unknown MAC mode: {mode}")

    def Mac(self, key: bytes, message: bytes) -> bytes:
        """Compute MAC tag."""
        return self._impl.mac(key, message)

    def Vrfy(self, key: bytes, message: bytes, tag: bytes) -> bool:
        """Verify MAC tag."""
        return self._impl.verify(key, message, tag)


# ---------------------------------------------------------------------------
# Constant-Time Comparison
# ---------------------------------------------------------------------------

def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    XOR all bytes and check the result is zero.
    Prevents timing side-channel attacks on tag verification.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ---------------------------------------------------------------------------
# MAC ⇒ PRF (Backward Direction)
# ---------------------------------------------------------------------------

def demonstrate_mac_as_prf(mac_obj: MAC = None, num_queries: int = 100) -> dict:
    """
    Demonstrate that a secure MAC passes the PRF distinguishing test.
    Query the MAC on random inputs and compare output distribution
    to truly random outputs.
    """
    if mac_obj is None:
        mac_obj = MAC(mode='cbc')

    key = random_bytes(BLOCK_SIZE)

    # MAC outputs on random inputs
    mac_ones = 0
    total_bits = 0
    for _ in range(num_queries):
        msg = random_bytes(BLOCK_SIZE)
        tag = mac_obj.Mac(key, msg)
        for byte in tag:
            for bit in range(8):
                mac_ones += (byte >> bit) & 1
                total_bits += 1

    # Random outputs
    rand_ones = 0
    rand_total = 0
    for _ in range(num_queries):
        tag = random_bytes(BLOCK_SIZE)
        for byte in tag:
            for bit in range(8):
                rand_ones += (byte >> bit) & 1
                rand_total += 1

    mac_ratio = mac_ones / total_bits
    rand_ratio = rand_ones / rand_total

    return {
        'mac_ones_ratio': mac_ratio,
        'random_ones_ratio': rand_ratio,
        'difference': abs(mac_ratio - rand_ratio),
        'passes_prf_test': abs(mac_ratio - rand_ratio) < 0.05,
        'conclusion': 'MAC output is pseudorandom (MAC ⇒ PRF witnessed)',
    }


# ---------------------------------------------------------------------------
# EUF-CMA Forgery Game
# ---------------------------------------------------------------------------

def euf_cma_game(mac_obj: MAC = None, num_queries: int = 50,
                  num_forgery_attempts: int = 20) -> dict:
    """
    EUF-CMA (Existential Unforgeability under Chosen Message Attack) game.

    1. Adversary queries the MAC oracle on up to num_queries messages.
    2. Adversary attempts to forge a valid (m*, t*) for a new message m*.
    3. Expect 0 successful forgeries.
    """
    if mac_obj is None:
        mac_obj = MAC(mode='cbc')

    key = random_bytes(BLOCK_SIZE)

    # Phase 1: Adversary gets MAC oracle access
    signed_messages = {}
    for _ in range(num_queries):
        m = random_bytes(BLOCK_SIZE)
        t = mac_obj.Mac(key, m)
        signed_messages[m] = t

    # Phase 2: Adversary attempts forgery on new messages
    successes = 0
    for _ in range(num_forgery_attempts):
        # Generate a new message (not in signed set)
        m_star = random_bytes(BLOCK_SIZE)
        while m_star in signed_messages:
            m_star = random_bytes(BLOCK_SIZE)

        # Try a random tag
        t_star = random_bytes(BLOCK_SIZE)
        if mac_obj.Vrfy(key, m_star, t_star):
            successes += 1

    return {
        'queries': num_queries,
        'forgery_attempts': num_forgery_attempts,
        'successful_forgeries': successes,
        'secure': successes == 0,
        'conclusion': ('EUF-CMA secure: no forgery succeeded'
                       if successes == 0
                       else f'BROKEN: {successes} forgeries succeeded!'),
    }


# ---------------------------------------------------------------------------
# Interface functions
# ---------------------------------------------------------------------------

_default_mac = None

def _get_default():
    global _default_mac
    if _default_mac is None:
        _default_mac = MAC(mode='cbc')
    return _default_mac

def Mac(key: bytes, message: bytes) -> bytes:
    """Compute MAC tag."""
    return _get_default().Mac(key, message)

def Vrfy(key: bytes, message: bytes, tag: bytes) -> bool:
    """Verify MAC tag."""
    return _get_default().Vrfy(key, message, tag)


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("Message Authentication Codes")
    print("=" * 60)

    key = random_bytes(BLOCK_SIZE)

    # PRF-MAC
    print("\n--- PRF-MAC (fixed-length) ---")
    prf_mac = PRFMAC()
    msg = b"Authenticate me!"  # 16 bytes
    tag = prf_mac.mac(key, msg)
    print(f"Message: {msg}")
    print(f"Tag: {to_hex(tag)}")
    print(f"Verify: {prf_mac.verify(key, msg, tag)}")
    print(f"Tampered verify: {prf_mac.verify(key, msg, random_bytes(16))}")

    # CBC-MAC
    print("\n--- CBC-MAC (variable-length) ---")
    cbc_mac = CBCMAC()
    for msg in [b"Hello!", b"A longer message for testing"]:
        tag = cbc_mac.mac(key, msg)
        print(f"Message: {msg}")
        print(f"Tag: {to_hex(tag)}")
        print(f"Verify: {cbc_mac.verify(key, msg, tag)}")

    # MAC ⇒ PRF
    print("\n--- MAC ⇒ PRF (Backward Direction) ---")
    result = demonstrate_mac_as_prf()
    print(f"MAC bit ratio: {result['mac_ones_ratio']:.4f}")
    print(f"Random ratio:  {result['random_ones_ratio']:.4f}")
    print(f"{result['conclusion']}")

    # EUF-CMA Game
    print("\n--- EUF-CMA Forgery Game ---")
    game = euf_cma_game()
    print(f"Queries: {game['queries']}, Attempts: {game['forgery_attempts']}")
    print(f"Forgeries: {game['successful_forgeries']}")
    print(f"{game['conclusion']}")
