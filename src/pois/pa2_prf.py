from __future__ import annotations

from dataclasses import dataclass

from .common import bits_from_bytes, int_to_bytes, bytes_to_int
from .pa1_owf_prg import PRGFromOWF


def split_halves(b: bytes) -> tuple[bytes, bytes]:
    n = len(b) // 2
    return b[:n], b[n:]


@dataclass
class GGMPRF:
    prg: PRGFromOWF
    n_bytes: int = 16

    def F(self, k: bytes, x_bits: str) -> bytes:
        if any(b not in "01" for b in x_bits):
            raise ValueError("x_bits must be a bit string")
        s = k
        for bit in x_bits:
            self.prg.seed(s)
            expanded = self.prg.next_bits(self.n_bytes * 16)
            left, right = split_halves(expanded)
            s = left if bit == "0" else right
        return s


class ToyAESPRF:
    """Small stand-in for AES-based PRF (educational only)."""

    block_size = 16

    @staticmethod
    def F(k: bytes, x: bytes) -> bytes:
        if len(k) < 16:
            k = (k * ((16 // len(k)) + 1))[:16]
        if len(x) < 16:
            x = x.ljust(16, b"\x00")
        state = bytes_to_int(k[:16]) ^ bytes_to_int(x[:16])
        # 6 Feistel-like toy rounds.
        l = (state >> 64) & ((1 << 64) - 1)
        r = state & ((1 << 64) - 1)
        for i in range(6):
            f = ((r * 0x9E3779B185EBCA87) + i) & ((1 << 64) - 1)
            l, r = r, l ^ f
        out = (l << 64) | r
        return int_to_bytes(out, 16)

    @staticmethod
    def D(k: bytes, y: bytes) -> bytes:
        if len(k) < 16:
            k = (k * ((16 // len(k)) + 1))[:16]
        if len(y) < 16:
            y = y.ljust(16, b"\x00")
        state = bytes_to_int(y[:16])
        l = (state >> 64) & ((1 << 64) - 1)
        r = state & ((1 << 64) - 1)
        for i in range(5, -1, -1):
            prev_r = l
            f = ((prev_r * 0x9E3779B185EBCA87) + i) & ((1 << 64) - 1)
            prev_l = r ^ f
            l, r = prev_l, prev_r
        out = ((l << 64) | r) ^ bytes_to_int(k[:16])
        return int_to_bytes(out, 16)


def prg_from_prf(prf_fn, s: bytes, n_bytes: int = 16) -> bytes:
    """PRF => PRG: G(s) = F_s(0n) || F_s(1n)."""
    zero = b"\x00" * n_bytes
    one = (b"\x00" * (n_bytes - 1)) + b"\x01"
    # Handle both byte-based and bit-string-based PRF interfaces
    try:
        # Try ToyAESPRF interface (bytes input)
        return prf_fn(s, zero) + prf_fn(s, one)
    except (TypeError, ValueError):
        # Try GGMPRF interface (bit string input)
        zero_bits = "0" * (n_bytes * 8)
        one_bits = "0" * (n_bytes * 8 - 1) + "1"
        return prf_fn(s, zero_bits) + prf_fn(s, one_bits)


def prf_distinguishing_demo(prf_fn, q: int = 100, n_bytes: int = 16) -> dict[str, float]:
    # Empirical check: compare bit-balance only, not a proof.
    ones_prf = 0
    ones_rand = 0
    total = 0
    for i in range(q):
        k = int_to_bytes(i + 1, n_bytes)
        x = int_to_bytes(i * 17 + 3, n_bytes)
        y1 = prf_fn(k, x)
        y2 = int_to_bytes((i * 1103515245 + 12345) % (1 << (8 * n_bytes)), n_bytes)
        bits1 = bits_from_bytes(y1)
        bits2 = bits_from_bytes(y2)
        ones_prf += sum(bits1)
        ones_rand += sum(bits2)
        total += len(bits1)
    return {
        "prf_one_ratio": ones_prf / total,
        "rand_one_ratio": ones_rand / total,
        "abs_gap": abs(ones_prf - ones_rand) / total,
    }


def prg_from_prf_demo(prf_fn, seed: bytes, n_bytes: int = 16) -> dict[str, float]:
    out = prg_from_prf(prf_fn, seed, n_bytes)
    bits = bits_from_bytes(out)
    ratio = sum(bits) / len(bits)
    return {
        "length": float(len(out)),
        "one_ratio": ratio,
    }
