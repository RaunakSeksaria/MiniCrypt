from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from .common import modexp, random_odd_int


@dataclass
class MillerRabinTrace:
    witness: int
    x0: int
    squarings: list[int]
    composite: bool


def miller_rabin(n: int, k: int = 40, return_trace: bool = False):
    if n < 2:
        return (False, []) if return_trace else False
    if n in (2, 3):
        return (True, []) if return_trace else True
    if n % 2 == 0:
        return (False, []) if return_trace else False

    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    traces: list[MillerRabinTrace] = []
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = modexp(a, d, n)
        x0 = x
        sq: list[int] = []
        if x in (1, n - 1):
            traces.append(MillerRabinTrace(a, x, sq, composite=False))
            continue
        witnessed_composite = True
        for _r in range(s - 1):
            x = (x * x) % n
            sq.append(x)
            if x == n - 1:
                witnessed_composite = False
                break
        traces.append(MillerRabinTrace(a, x0, sq, witnessed_composite))
        if witnessed_composite:
            return (False, traces) if return_trace else False
    return (True, traces) if return_trace else True


def is_prime(n: int, k: int = 40) -> bool:
    return bool(miller_rabin(n, k))


def gen_prime(bits: int, k: int = 40) -> int:
    while True:
        n = random_odd_int(bits)
        if is_prime(n, k):
            return n


def fermat_primality(n: int, a: int = 2) -> bool:
    if n <= 2:
        return n == 2
    if n % 2 == 0:
        return False
    return modexp(a, n - 1, n) == 1


def carmichael_demo() -> dict[str, bool]:
    n = 561
    return {
        "fermat_passes": fermat_primality(n, 2),
        "miller_rabin_rejects": not is_prime(n, 10),
    }


def prime_generation_benchmark(bits: int, samples: int = 5, k: int = 40) -> dict[str, float]:
    counts = []
    t0 = time.perf_counter()
    for _ in range(samples):
        c = 0
        while True:
            c += 1
            n = random_odd_int(bits)
            if is_prime(n, k):
                counts.append(c)
                break
    t1 = time.perf_counter()
    return {
        "avg_candidates": sum(counts) / len(counts),
        "seconds": t1 - t0,
    }
