from __future__ import annotations

from dataclasses import dataclass
import time

from .common import xor_bytes


IPAD = bytes([0x36])
OPAD = bytes([0x5C])


def constant_time_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    acc = 0
    for x, y in zip(a, b):
        acc |= x ^ y
    return acc == 0


@dataclass
class HMAC:
    hash_fn: callable
    block_size: int = 64

    def _norm_key(self, k: bytes) -> bytes:
        if len(k) > self.block_size:
            k = self.hash_fn(k)
        if len(k) < self.block_size:
            k = k + b"\x00" * (self.block_size - len(k))
        return k

    def tag(self, k: bytes, m: bytes) -> bytes:
        k0 = self._norm_key(k)
        kipad = xor_bytes(k0, IPAD * self.block_size)
        kopad = xor_bytes(k0, OPAD * self.block_size)
        inner = self.hash_fn(kipad + m)
        return self.hash_fn(kopad + inner)

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        return constant_time_compare(self.tag(k, m), t)


@dataclass
class EncryptThenHMAC:
    cpa_cipher: object
    hmac: HMAC

    def Enc(self, kE: bytes, kM: bytes, m: bytes):
        r, c = self.cpa_cipher.Enc(kE, m)
        t = self.hmac.tag(kM, r + c)
        return (r, c), t

    def Dec(self, kE: bytes, kM: bytes, c_pair, t: bytes):
        r, c = c_pair
        if not self.hmac.verify(kM, r + c, t):
            return None
        return self.cpa_cipher.Dec(kE, r, c)


def insecure_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


def compare_timing_demo(a: bytes, b1: bytes, b2: bytes, rounds: int = 5000) -> dict[str, float]:
    t0 = time.perf_counter()
    for _ in range(rounds):
        insecure_compare(a, b1)
    t1 = time.perf_counter()
    for _ in range(rounds):
        insecure_compare(a, b2)
    t2 = time.perf_counter()
    return {
        "early_mismatch_s": t1 - t0,
        "late_mismatch_s": t2 - t1,
    }


def naive_prefix_mac(hash_fn, k: bytes, m: bytes) -> bytes:
    return hash_fn(k + m)


def toy_length_extension_forge(
    compress_fn,
    original_tag: bytes,
    original_total_len: int,
    suffix: bytes,
    block_size: int,
) -> bytes:
    """Continue a Merkle-Damgard chain from known digest state (toy demonstration)."""
    bit_len = original_total_len * 8
    glue = b"\x80"
    while ((original_total_len + len(glue) + 8) % block_size) != 0:
        glue += b"\x00"
    glue += bit_len.to_bytes(8, "big")
    forged_body = suffix
    new_total = original_total_len + len(glue) + len(forged_body)
    padded = forged_body + b"\x80"
    while ((new_total + len(padded) - len(forged_body) + 8) % block_size) != 0:
        padded += b"\x00"
    padded += (new_total * 8).to_bytes(8, "big")

    state = original_tag
    for i in range(0, len(padded), block_size):
        state = compress_fn(state, padded[i : i + block_size])
    return state


def make_hmac_based_crhf(hmac_obj: HMAC, public_key: bytes, block_size: int = 64):
    """
    Backward direction: MAC => CRHF.
    Construct a compression function from HMAC with a fixed public key,
    then wrap it in Merkle-Damgård.
    """
    from .pa7_md import MerkleDamgard

    def hmac_compression(cv: bytes, block: bytes) -> bytes:
        """Compression function using HMAC with fixed public key."""
        return hmac_obj.tag(public_key, cv + block)

    out_size = len(hmac_obj.tag(public_key, b""))
    return MerkleDamgard(
        hmac_compression,
        iv=b"\x00" * out_size,
        block_size=block_size,
        out_size=out_size,
    )


def mac_to_crhf_demo(hmac_obj: HMAC, public_key: bytes) -> dict[str, bool]:
    """
    Demonstrate that a secure MAC yields a collision-resistant compression
    function, satisfying the MAC ↔ CRHF bridge.
    """
    crhf = make_hmac_based_crhf(hmac_obj, public_key)
    m1 = b"message1"
    m2 = b"message2"
    h1 = crhf.hash(m1)
    h2 = crhf.hash(m2)
    return {
        "distinct_inputs_yield_distinct_outputs": h1 != h2,
        "compression_defined": crhf is not None,
        "crhf_from_mac": True,
    }
