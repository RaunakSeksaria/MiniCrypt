from __future__ import annotations

import secrets
from dataclasses import dataclass

from .pa16_elgamal import ElGamalPrivateKey, ElGamalPublicKey, elgamal_dec, elgamal_enc, elgamal_keygen


@dataclass
class OTState:
    b: int
    sk_b: ElGamalPrivateKey


def ot_receiver_step1(params, b: int):
    pk_b, sk_b = elgamal_keygen(params)
    # Fake key without trapdoor for other branch.
    fake_h = secrets.randbelow(params.p - 3) + 2
    pk_other = ElGamalPublicKey(params, fake_h)
    if b == 0:
        return pk_b, pk_other, OTState(b, sk_b)
    return pk_other, pk_b, OTState(b, sk_b)


def ot_sender_step(pk0: ElGamalPublicKey, pk1: ElGamalPublicKey, m0: int, m1: int):
    c0 = elgamal_enc(pk0, m0)
    c1 = elgamal_enc(pk1, m1)
    return c0, c1


def ot_receiver_step2(state: OTState, c0, c1):
    return elgamal_dec(state.sk_b, *(c0 if state.b == 0 else c1))


def ot_trial(params, b: int, m0: int, m1: int) -> int:
    pk0, pk1, st = ot_receiver_step1(params, b)
    c0, c1 = ot_sender_step(pk0, pk1, m0, m1)
    return ot_receiver_step2(st, c0, c1)


def ot_correctness_demo(params, trials: int = 100) -> bool:
    for i in range(trials):
        b = i & 1
        m0 = 100 + i
        m1 = 200 + i
        out = ot_trial(params, b, m0, m1)
        if out != (m0 if b == 0 else m1):
            return False
    return True
