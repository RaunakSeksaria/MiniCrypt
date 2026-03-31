from __future__ import annotations

from .common import modinv, modexp
from .pa12_rsa import RSAPrivateKey
import time


def crt(residues: list[int], moduli: list[int]) -> int:
    N = 1
    for n in moduli:
        N *= n
    x = 0
    for a, n in zip(residues, moduli):
        Mi = N // n
        inv = modinv(Mi, n)
        x = (x + a * Mi * inv) % N
    return x


def rsa_dec_crt(sk: RSAPrivateKey, c: int) -> int:
    mp = modexp(c % sk.p, sk.dp, sk.p)
    mq = modexp(c % sk.q, sk.dq, sk.q)
    h = (sk.q_inv * (mp - mq)) % sk.p
    return mq + h * sk.q


def integer_nth_root(x: int, n: int) -> int:
    if x == 0:
        return 0
    r = int(x ** (1 / n))
    while (r + 1) ** n <= x:
        r += 1
    while r**n > x:
        r -= 1
    return r


def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> int:
    x = crt(ciphertexts, moduli)
    return integer_nth_root(x, e)


def rsa_crt_speedup_demo(sk: RSAPrivateKey, ciphertexts: list[int]) -> dict[str, float]:
    t0 = time.perf_counter()
    for c in ciphertexts:
        _ = modexp(c, sk.d, sk.N)
    t1 = time.perf_counter()
    for c in ciphertexts:
        _ = rsa_dec_crt(sk, c)
    t2 = time.perf_counter()
    normal = t1 - t0
    crt_t = t2 - t1
    return {
        "normal_seconds": normal,
        "crt_seconds": crt_t,
        "speedup": (normal / crt_t) if crt_t > 0 else float("inf"),
    }


def hastad_attack_bound_bytes(moduli: list[int], e: int) -> int:
    N = 1
    for n in moduli:
        N *= n
    m_max = integer_nth_root(N - 1, e)
    return max(1, (m_max.bit_length() + 7) // 8)
