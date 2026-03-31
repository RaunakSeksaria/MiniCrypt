from __future__ import annotations

from dataclasses import dataclass

from .common import bytes_to_int
from .pa12_rsa import RSAPrivateKey, RSAPublicKey, rsa_dec, rsa_enc


@dataclass
class RSASignatureScheme:
    hash_fn: callable

    def Sign(self, sk: RSAPrivateKey, m: bytes) -> int:
        h = bytes_to_int(self.hash_fn(m)) % sk.N
        return rsa_dec(sk, h)

    def Verify(self, pk: RSAPublicKey, m: bytes, sigma: int) -> bool:
        h = bytes_to_int(self.hash_fn(m)) % pk.N
        return rsa_enc(pk, sigma) == h


def raw_rsa_multiplicative_forgery(pk: RSAPublicKey, sig_m1: int, sig_m2: int) -> int:
    return (sig_m1 * sig_m2) % pk.N


def euf_cma_signature_demo(sig_scheme: RSASignatureScheme, sk: RSAPrivateKey, pk: RSAPublicKey, queries: int = 50) -> dict[str, bool | int]:
    signed: set[bytes] = set()
    for i in range(queries):
        m = f"signed-{i}".encode()
        _ = sig_scheme.Sign(sk, m)
        signed.add(m)
    m_star = b"new-message"
    sigma_star = 0
    return {
        "new_message": m_star not in signed,
        "forgery_accepts": sig_scheme.Verify(pk, m_star, sigma_star),
        "queries": queries,
    }
