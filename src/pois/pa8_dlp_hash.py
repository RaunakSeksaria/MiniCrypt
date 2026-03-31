from __future__ import annotations

from dataclasses import dataclass
import random

from .common import bytes_to_int, int_to_bytes
from .pa1_owf_prg import DLPParams
from .pa7_md import MerkleDamgard


@dataclass
class DLPCompression:
    params: DLPParams
    h_hat: int
    out_bytes: int = 16

    def __call__(self, cv: bytes, blk: bytes) -> bytes:
        x = bytes_to_int(cv) % self.params.q
        y = bytes_to_int(blk) % self.params.q
        out = (pow(self.params.g, x, self.params.p) * pow(self.h_hat, y, self.params.p)) % self.params.p
        return int_to_bytes(out % (1 << (8 * self.out_bytes)), self.out_bytes)


def make_dlp_hash(params: DLPParams, alpha: int = 7, block_size: int = 16, out_bytes: int = 16):
    h_hat = pow(params.g, alpha % params.q, params.p)
    comp = DLPCompression(params, h_hat, out_bytes)
    md = MerkleDamgard(comp, iv=b"\x00" * out_bytes, block_size=block_size, out_size=out_bytes)
    return md


def dlp_hash_bytes(params: DLPParams, message: bytes, out_bytes: int = 16, alpha: int = 7) -> bytes:
    return make_dlp_hash(params, alpha=alpha, out_bytes=out_bytes).hash(message)


def tiny_collision_search(params: DLPParams, out_bits: int = 16, max_iters: int = 20000) -> tuple[bytes, bytes, bytes] | None:
    """Birthday-style collision hunt on truncated DLP hash for toy parameters."""
    mask = (1 << out_bits) - 1
    h = make_dlp_hash(params, out_bytes=max(2, (out_bits + 7) // 8)).hash
    seen: dict[int, bytes] = {}
    for _ in range(max_iters):
        m = random.randbytes(8)
        d = int.from_bytes(h(m), "big") & mask
        if d in seen and seen[d] != m:
            shared = d.to_bytes((out_bits + 7) // 8, "big")
            return seen[d], m, shared
        seen[d] = m
    return None
