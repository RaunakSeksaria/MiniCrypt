from __future__ import annotations

from dataclasses import dataclass

from .common import chunk, xor_bytes
from .pa10_hmac import HMAC


@dataclass
class PRFMAC:
    prf_fn: callable
    block_size: int = 16

    def Mac(self, k: bytes, m: bytes) -> bytes:
        if len(m) != self.block_size:
            raise ValueError("PRF-MAC is fixed-length single block")
        return self.prf_fn(k, m)[: self.block_size]

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        return self.Mac(k, m) == t


@dataclass
class CBCMAC:
    prf_fn: callable
    block_size: int = 16

    def _pad(self, m: bytes) -> bytes:
        n = self.block_size - (len(m) % self.block_size)
        if n == 0:
            n = self.block_size
        return m + bytes([n]) * n

    def Mac(self, k: bytes, m: bytes) -> bytes:
        state = b"\x00" * self.block_size
        for blk in chunk(self._pad(m), self.block_size):
            state = self.prf_fn(k, xor_bytes(state, blk))[: self.block_size]
        return state

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        return self.Mac(k, m) == t


def hmac_stub(_k: bytes, _m: bytes) -> bytes:
    # Backward-compatible fallback based on a tiny non-crypto hash.
    def _toy_hash(data: bytes) -> bytes:
        acc = 0
        for b in data:
            acc = ((acc * 131) ^ b) & ((1 << 128) - 1)
        return acc.to_bytes(16, "big")

    return hmac_from_hash(_toy_hash, _k, _m, block_size=64)


def hmac_from_hash(hash_fn, k: bytes, m: bytes, block_size: int = 64) -> bytes:
    return HMAC(hash_fn=hash_fn, block_size=block_size).tag(k, m)


def hmac_verify_from_hash(hash_fn, k: bytes, m: bytes, t: bytes, block_size: int = 64) -> bool:
    return HMAC(hash_fn=hash_fn, block_size=block_size).verify(k, m, t)


def euf_cma_demo(mac, k: bytes, attempts: int = 50) -> bool:
    seen: set[bytes] = set()
    tags: dict[bytes, bytes] = {}
    for i in range(attempts):
        m = f"msg-{i}".encode()
        t = mac.Mac(k, m if hasattr(mac, "_pad") else m.ljust(16, b"\x00")[:16])
        seen.add(m)
        tags[m] = t
    forge_m = b"forge-new"
    if hasattr(mac, "_pad"):
        forged_tag = tags[next(iter(tags))]
        return mac.Vrfy(k, forge_m, forged_tag)
    return False


def euf_cma_game(mac, k: bytes, oracle_queries: int = 50) -> dict[str, int | bool]:
    """Return a tiny EUF-CMA experiment summary.

    forged is True only if a naive forgery unexpectedly succeeds.
    """
    seen: set[bytes] = set()
    for i in range(oracle_queries):
        m = f"oracle-{i}".encode()
        seen.add(m)
        _ = mac.Mac(k, m if hasattr(mac, "_pad") else m.ljust(16, b"\x00")[:16])

    candidate = b"new-message-for-forgery"
    if candidate in seen:
        candidate += b"!"

    bogus = b"\x00" * getattr(mac, "block_size", 16)
    forged = mac.Vrfy(k, candidate if hasattr(mac, "_pad") else candidate[:16].ljust(16, b"\x00"), bogus)
    return {
        "queries": oracle_queries,
        "forged": forged,
        "new_message": candidate not in seen,
    }
