from __future__ import annotations

import random
import math
from dataclasses import dataclass


@dataclass
class CollisionResult:
    x1: bytes
    x2: bytes
    digest: bytes
    evaluations: int


def birthday_attack(hash_fn, n_bits: int, max_iters: int = 1_000_000) -> CollisionResult | None:
    seen: dict[int, bytes] = {}
    mask = (1 << n_bits) - 1
    for i in range(1, max_iters + 1):
        x = random.randbytes(8)
        h = int.from_bytes(hash_fn(x), "big") & mask
        if h in seen and seen[h] != x:
            d = h.to_bytes((n_bits + 7) // 8, "big")
            return CollisionResult(seen[h], x, d, i)
        seen[h] = x
    return None


def floyd_cycle_collision(hash_iter_fn, seed: int) -> tuple[int, int, int]:
    tortoise = hash_iter_fn(seed)
    hare = hash_iter_fn(hash_iter_fn(seed))
    while tortoise != hare:
        tortoise = hash_iter_fn(tortoise)
        hare = hash_iter_fn(hash_iter_fn(hare))
    mu = 0
    tortoise = seed
    while tortoise != hare:
        tortoise = hash_iter_fn(tortoise)
        hare = hash_iter_fn(hare)
        mu += 1
    lam = 1
    hare = hash_iter_fn(tortoise)
    while tortoise != hare:
        hare = hash_iter_fn(hare)
        lam += 1
    return tortoise, mu, lam


def empirical_collision_trials(hash_fn, n_bits: int, trials: int = 100, max_iters: int = 1_000_000) -> list[int]:
    out: list[int] = []
    for _ in range(trials):
        r = birthday_attack(hash_fn, n_bits=n_bits, max_iters=max_iters)
        out.append(r.evaluations if r is not None else max_iters)
    return out


def theoretical_collision_probability(k: int, n_bits: int) -> float:
    return 1.0 - math.exp(-(k * (k - 1)) / (2 ** (n_bits + 1)))


def birthday_work_factor(n_bits: int) -> int:
    return 1 << (n_bits // 2)


def hash_time_estimate_seconds(n_bits: int, hashes_per_second: int = 10**9) -> float:
    return birthday_work_factor(n_bits) / float(hashes_per_second)
