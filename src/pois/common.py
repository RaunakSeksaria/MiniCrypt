from __future__ import annotations

import math
import os
import random
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Iterable, List, Sequence, Tuple


def randbytes(n: int) -> bytes:
    return os.urandom(n)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def chunk(data: bytes, size: int) -> List[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    n = block_size - (len(data) % block_size)
    if n == 0:
        n = block_size
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padded data")
    n = data[-1]
    if n < 1 or n > block_size or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-n]


def int_to_bytes(x: int, length: int | None = None) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    if length is None:
        length = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def modexp(base: int, exp: int, mod: int) -> int:
    # Square-and-multiply required by PA#12/#13.
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, n: int) -> int:
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % n


def monobit_test(bits: Sequence[int]) -> Tuple[bool, float]:
    ones = sum(bits)
    zeros = len(bits) - ones
    s = abs(ones - zeros) / math.sqrt(len(bits)) if bits else 0.0
    p_value = math.erfc(s / math.sqrt(2.0))
    return p_value >= 0.01, p_value


def runs_test(bits: Sequence[int]) -> Tuple[bool, float]:
    if not bits:
        return False, 0.0
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return False, 0.0
    v = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    num = abs(v - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(num / den) if den else 0.0
    return p_value >= 0.01, p_value


def serial_test(bits: Sequence[int]) -> Tuple[bool, float]:
    if len(bits) < 2:
        return False, 0.0
    c00 = c01 = c10 = c11 = 0
    for i in range(len(bits) - 1):
        pair = (bits[i], bits[i + 1])
        if pair == (0, 0):
            c00 += 1
        elif pair == (0, 1):
            c01 += 1
        elif pair == (1, 0):
            c10 += 1
        else:
            c11 += 1
    total = c00 + c01 + c10 + c11
    expected = total / 4
    chi2 = sum((c - expected) ** 2 / expected for c in (c00, c01, c10, c11) if expected)
    p_value = math.exp(-chi2 / 2)
    return p_value >= 0.01, p_value


def bits_from_bytes(b: bytes) -> List[int]:
    out: List[int] = []
    for byte in b:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


@dataclass
class BenchResult:
    name: str
    seconds: float


def benchmark(name: str, fn: Callable[[], object], rounds: int) -> BenchResult:
    start = time.perf_counter()
    for _ in range(rounds):
        fn()
    return BenchResult(name=name, seconds=time.perf_counter() - start)


def random_odd_int(bits: int) -> int:
    n = secrets.randbits(bits)
    n |= (1 << (bits - 1))
    n |= 1
    return n
