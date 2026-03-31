from __future__ import annotations

from dataclasses import dataclass

from .common import chunk, int_to_bytes, pkcs7_pad, pkcs7_unpad, randbytes, xor_bytes


@dataclass
class CPACipher:
    prf_fn: callable
    block_size: int = 16

    def Enc(self, k: bytes, m: bytes) -> tuple[bytes, bytes]:
        r = randbytes(self.block_size)
        m_pad = pkcs7_pad(m, self.block_size)
        ct = bytearray()
        counter = int.from_bytes(r, "big")
        for blk in chunk(m_pad, self.block_size):
            stream = self.prf_fn(k, int_to_bytes(counter, self.block_size))
            ct.extend(xor_bytes(blk, stream[: self.block_size]))
            counter += 1
        return r, bytes(ct)

    def Dec(self, k: bytes, r: bytes, c: bytes) -> bytes:
        out = bytearray()
        counter = int.from_bytes(r, "big")
        for blk in chunk(c, self.block_size):
            stream = self.prf_fn(k, int_to_bytes(counter, self.block_size))
            out.extend(xor_bytes(blk, stream[: self.block_size]))
            counter += 1
        return pkcs7_unpad(bytes(out), self.block_size)


class BrokenDeterministicCPA(CPACipher):
    def Enc(self, k: bytes, m: bytes) -> tuple[bytes, bytes]:
        r = b"\x00" * self.block_size
        m_pad = pkcs7_pad(m, self.block_size)
        ct = bytearray()
        counter = int.from_bytes(r, "big")
        for blk in chunk(m_pad, self.block_size):
            stream = self.prf_fn(k, int_to_bytes(counter, self.block_size))
            ct.extend(xor_bytes(blk, stream[: self.block_size]))
            counter += 1
        return r, bytes(ct)


def ind_cpa_game(cipher: CPACipher, k: bytes, m0: bytes, m1: bytes, b: int) -> tuple[tuple[bytes, bytes], int]:
    r, c = cipher.Enc(k, m0 if b == 0 else m1)
    return (r, c), b


def deterministic_reuse_attack(cipher: BrokenDeterministicCPA, k: bytes, m: bytes) -> bool:
    c1 = cipher.Enc(k, m)
    c2 = cipher.Enc(k, m)
    return c1 == c2
