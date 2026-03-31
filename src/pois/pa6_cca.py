from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EncryptThenMAC:
    cpa_cipher: object
    mac: object

    def CCA_Enc(self, kE: bytes, kM: bytes, m: bytes):
        r, c = self.cpa_cipher.Enc(kE, m)
        t = self.mac.Mac(kM, r + c)
        return (r, c), t

    def CCA_Dec(self, kE: bytes, kM: bytes, c_pair, t: bytes):
        r, c = c_pair
        if not self.mac.Vrfy(kM, r + c, t):
            return None
        return self.cpa_cipher.Dec(kE, r, c)


def key_separation_ok(kE: bytes, kM: bytes) -> bool:
    return kE != kM


def cpa_malleability_flip(c_pair, bit_index: int) -> tuple[bytes, bytes]:
    r, c = c_pair
    if not c:
        return r, c
    byte_i = max(0, min(len(c) - 1, bit_index // 8))
    bit_i = bit_index % 8
    mask = 1 << (7 - bit_i)
    c2 = bytearray(c)
    c2[byte_i] ^= mask
    return r, bytes(c2)


def ind_cca2_demo(etm: EncryptThenMAC, kE: bytes, kM: bytes, m0: bytes, m1: bytes, b: int) -> dict[str, bool]:
    challenge = etm.CCA_Enc(kE, kM, m0 if b == 0 else m1)
    (r, c), t = challenge
    # Adversary tampers ciphertext and queries decryption oracle.
    tampered = (r, c[:-1] + bytes([c[-1] ^ 1])) if c else (r, c)
    oracle_out = etm.CCA_Dec(kE, kM, tampered, t)
    return {
        "tamper_rejected": oracle_out is None,
        "key_separated": key_separation_ok(kE, kM),
    }
