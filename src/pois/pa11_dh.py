from __future__ import annotations

import secrets
from dataclasses import dataclass

from .pa1_owf_prg import find_generator
from .pa13_miller_rabin import gen_prime, is_prime


@dataclass
class DHParams:
    p: int
    q: int
    g: int


def gen_dh_params(bits: int = 64) -> DHParams:
    while True:
        q = gen_prime(bits - 1, 20)
        p = 2 * q + 1
        if is_prime(p, 20):
            return DHParams(p=p, q=q, g=find_generator(p, q))


def dh_alice_step1(params: DHParams):
    a = secrets.randbelow(params.q - 2) + 2
    A = pow(params.g, a, params.p)
    return a, A


def dh_bob_step1(params: DHParams):
    b = secrets.randbelow(params.q - 2) + 2
    B = pow(params.g, b, params.p)
    return b, B


def dh_alice_step2(params: DHParams, a: int, B: int) -> int:
    return pow(B, a, params.p)


def dh_bob_step2(params: DHParams, b: int, A: int) -> int:
    return pow(A, b, params.p)


def mitm_demo(params: DHParams):
    a, A = dh_alice_step1(params)
    b, B = dh_bob_step1(params)
    e = secrets.randbelow(params.q - 2) + 2
    E = pow(params.g, e, params.p)
    KA = dh_alice_step2(params, a, E)
    KB = dh_bob_step2(params, b, E)
    KEA = pow(A, e, params.p)
    KEB = pow(B, e, params.p)
    return KA, KB, KEA, KEB


def dh_exchange(params: DHParams) -> tuple[int, int, int, int]:
    a, A = dh_alice_step1(params)
    b, B = dh_bob_step1(params)
    KA = dh_alice_step2(params, a, B)
    KB = dh_bob_step2(params, b, A)
    return A, B, KA, KB


def cdh_bruteforce_demo(params: DHParams, A: int, B: int, max_exp: int = 1 << 16) -> int | None:
    """Try solving CDH by recovering discrete log in tiny groups only."""
    for guess_a in range(1, min(max_exp, params.q)):
        if pow(params.g, guess_a, params.p) == A:
            return pow(B, guess_a, params.p)
    return None
