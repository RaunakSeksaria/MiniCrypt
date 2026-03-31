from __future__ import annotations

import os
import math
from dataclasses import dataclass

from .common import bytes_to_int, int_to_bytes, modexp, modinv
from .pa13_miller_rabin import gen_prime


@dataclass
class RSAPublicKey:
    N: int
    e: int


@dataclass
class RSAPrivateKey:
    N: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    q_inv: int


def rsa_keygen(bits: int = 512, e: int = 65537):
    while True:
        p = gen_prime(bits // 2, 40)
        q = gen_prime(bits // 2, 40)
        while p == q:
            q = gen_prime(bits // 2, 40)
        N = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            break
    pk = RSAPublicKey(N=N, e=e)
    sk = RSAPrivateKey(N=N, d=d, p=p, q=q, dp=d % (p - 1), dq=d % (q - 1), q_inv=modinv(q, p))
    return pk, sk


def rsa_enc(pk: RSAPublicKey, m: int) -> int:
    return modexp(m, pk.e, pk.N)


def rsa_dec(sk: RSAPrivateKey, c: int) -> int:
    return modexp(c, sk.d, sk.N)


def pkcs15_pad(m: bytes, k: int) -> bytes:
    if len(m) > k - 11:
        raise ValueError("message too long")
    ps_len = k - len(m) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b"\x00":
            ps += b
    return b"\x00\x02" + bytes(ps) + b"\x00" + m


def pkcs15_unpad(em: bytes) -> bytes:
    if len(em) < 11 or em[0:2] != b"\x00\x02":
        raise ValueError("bad padding")
    sep = em.find(b"\x00", 2)
    if sep < 10:
        raise ValueError("bad padding")
    return em[sep + 1 :]


def pkcs15_enc(pk: RSAPublicKey, m: bytes) -> int:
    k = (pk.N.bit_length() + 7) // 8
    em = pkcs15_pad(m, k)
    return rsa_enc(pk, bytes_to_int(em))


def pkcs15_dec(sk: RSAPrivateKey, c: int) -> bytes | None:
    k = (sk.N.bit_length() + 7) // 8
    em = int_to_bytes(rsa_dec(sk, c), k)
    try:
        return pkcs15_unpad(em)
    except ValueError:
        return None


def textbook_determinism_demo(pk: RSAPublicKey, m: int) -> bool:
    c1 = rsa_enc(pk, m)
    c2 = rsa_enc(pk, m)
    return c1 == c2


def pkcs15_randomized_demo(pk: RSAPublicKey, m: bytes) -> bool:
    c1 = pkcs15_enc(pk, m)
    c2 = pkcs15_enc(pk, m)
    return c1 != c2


def pkcs15_padding_oracle(sk: RSAPrivateKey, c: int) -> bool:
    return pkcs15_dec(sk, c) is not None
