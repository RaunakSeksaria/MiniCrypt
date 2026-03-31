from __future__ import annotations

import secrets
from dataclasses import dataclass

from .common import modinv
from .pa11_dh import DHParams


@dataclass
class ElGamalPublicKey:
    params: DHParams
    h: int


@dataclass
class ElGamalPrivateKey:
    params: DHParams
    x: int


def elgamal_keygen(params: DHParams):
    x = secrets.randbelow(params.q - 2) + 2
    h = pow(params.g, x, params.p)
    return ElGamalPublicKey(params, h), ElGamalPrivateKey(params, x)


def elgamal_enc(pk: ElGamalPublicKey, m: int) -> tuple[int, int]:
    r = secrets.randbelow(pk.params.q - 2) + 2
    c1 = pow(pk.params.g, r, pk.params.p)
    c2 = (m % pk.params.p) * pow(pk.h, r, pk.params.p) % pk.params.p
    return c1, c2


def elgamal_dec(sk: ElGamalPrivateKey, c1: int, c2: int) -> int:
    s = pow(c1, sk.x, sk.params.p)
    return (c2 * modinv(s, sk.params.p)) % sk.params.p


def malleability_attack(c1: int, c2: int, p: int, factor: int = 2) -> tuple[int, int]:
    return c1, (c2 * factor) % p


def ind_cpa_elgamal_demo(pk: ElGamalPublicKey, sk: ElGamalPrivateKey, m0: int, m1: int, b: int) -> dict[str, bool]:
    c1, c2 = elgamal_enc(pk, m0 if b == 0 else m1)
    # A naive adversary guess based on parity of decrypted message.
    dec = elgamal_dec(sk, c1, c2)
    guess = 0 if (dec % 2) == (m0 % 2) else 1
    return {
        "correct_guess": guess == b,
        "decrypt_ok": dec in (m0 % pk.params.p, m1 % pk.params.p),
    }
