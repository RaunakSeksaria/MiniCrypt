from __future__ import annotations

from dataclasses import dataclass

from .common import chunk


@dataclass
class MerkleDamgard:
    compress: callable
    iv: bytes
    block_size: int
    out_size: int

    def md_pad(self, m: bytes) -> bytes:
        bit_len = len(m) * 8
        padded = m + b"\x80"
        while (len(padded) + 8) % self.block_size != 0:
            padded += b"\x00"
        padded += bit_len.to_bytes(8, "big")
        return padded

    def hash(self, m: bytes) -> bytes:
        z = self.iv
        for blk in chunk(self.md_pad(m), self.block_size):
            z = self.compress(z, blk)
        return z


def xor_compress(cv: bytes, blk: bytes) -> bytes:
    n = min(len(cv), len(blk))
    return bytes((cv[i] ^ blk[i]) for i in range(n))


def collision_propagation_demo(md: MerkleDamgard, m1: bytes, m2: bytes) -> bool:
    """Return True when a toy compression collision propagates to the full hash.

    For the XOR compression toy, crafted same-length inputs with equal XOR per block
    collide under the full Merkle-Damgard pipeline as well.
    """
    return md.hash(m1) == md.hash(m2)
