from __future__ import annotations

from dataclasses import dataclass

from .common import chunk, int_to_bytes, pkcs7_pad, pkcs7_unpad, randbytes, xor_bytes


@dataclass
class Modes:
    block_fn: callable
    block_dec_fn: callable | None = None
    block_size: int = 16

    def _E(self, k: bytes, b: bytes) -> bytes:
        return self.block_fn(k, b)[: self.block_size]

    def _D(self, k: bytes, b: bytes) -> bytes:
        if self.block_dec_fn is None:
            return self._E(k, b)
        return self.block_dec_fn(k, b)[: self.block_size]

    def CBC_Enc(self, k: bytes, m: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
        iv = iv or randbytes(self.block_size)
        blocks = chunk(pkcs7_pad(m, self.block_size), self.block_size)
        out = bytearray()
        prev = iv
        for blk in blocks:
            cur = self._E(k, xor_bytes(blk, prev))
            out.extend(cur)
            prev = cur
        return iv, bytes(out)

    def CBC_Dec(self, k: bytes, iv: bytes, c: bytes) -> bytes:
        out = bytearray()
        prev = iv
        for blk in chunk(c, self.block_size):
            p = xor_bytes(self._D(k, blk), prev)
            out.extend(p)
            prev = blk
        return pkcs7_unpad(bytes(out), self.block_size)

    def OFB_Enc(self, k: bytes, m: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
        iv = iv or randbytes(self.block_size)
        data = pkcs7_pad(m, self.block_size)
        out = bytearray()
        state = iv
        for blk in chunk(data, self.block_size):
            state = self._E(k, state)
            out.extend(xor_bytes(blk, state))
        return iv, bytes(out)

    def OFB_Dec(self, k: bytes, iv: bytes, c: bytes) -> bytes:
        out = bytearray()
        state = iv
        for blk in chunk(c, self.block_size):
            state = self._E(k, state)
            out.extend(xor_bytes(blk, state[: len(blk)]))
        return pkcs7_unpad(bytes(out), self.block_size)

    def CTR_Enc(self, k: bytes, m: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
        nonce = nonce or randbytes(self.block_size)
        data = pkcs7_pad(m, self.block_size)
        out = bytearray()
        ctr = int.from_bytes(nonce, "big")
        for blk in chunk(data, self.block_size):
            ks = self._E(k, int_to_bytes(ctr, self.block_size))
            out.extend(xor_bytes(blk, ks))
            ctr += 1
        return nonce, bytes(out)

    def CTR_Dec(self, k: bytes, nonce: bytes, c: bytes) -> bytes:
        out = bytearray()
        ctr = int.from_bytes(nonce, "big")
        for blk in chunk(c, self.block_size):
            ks = self._E(k, int_to_bytes(ctr, self.block_size))
            out.extend(xor_bytes(blk, ks[: len(blk)]))
            ctr += 1
        return pkcs7_unpad(bytes(out), self.block_size)

    def Encrypt(self, mode: str, k: bytes, m: bytes):
        if mode == "CBC":
            return self.CBC_Enc(k, m)
        if mode == "OFB":
            return self.OFB_Enc(k, m)
        if mode == "CTR":
            return self.CTR_Enc(k, m)
        raise ValueError("unknown mode")

    def Decrypt(self, mode: str, k: bytes, iv_or_nonce: bytes, c: bytes):
        if mode == "CBC":
            return self.CBC_Dec(k, iv_or_nonce, c)
        if mode == "OFB":
            return self.OFB_Dec(k, iv_or_nonce, c)
        if mode == "CTR":
            return self.CTR_Dec(k, iv_or_nonce, c)
        raise ValueError("unknown mode")


def cbc_iv_reuse_leak_demo(modes: Modes, k: bytes, iv: bytes, m1: bytes, m2: bytes) -> bool:
    _iv1, c1 = modes.CBC_Enc(k, m1, iv)
    _iv2, c2 = modes.CBC_Enc(k, m2, iv)
    return c1[: modes.block_size] == c2[: modes.block_size]


def ofb_keystream_reuse_xor_demo(modes: Modes, k: bytes, iv: bytes, m1: bytes, m2: bytes) -> tuple[bytes, bytes]:
    _iv1, c1 = modes.OFB_Enc(k, m1, iv)
    _iv2, c2 = modes.OFB_Enc(k, m2, iv)
    n = min(len(c1), len(c2))
    return xor_bytes(c1[:n], c2[:n]), xor_bytes(pkcs7_pad(m1, modes.block_size)[:n], pkcs7_pad(m2, modes.block_size)[:n])


def roundtrip_lengths_demo(modes: Modes, k: bytes) -> dict[str, bool]:
    msgs = {
        "short": b"abc",
        "one_block": b"A" * modes.block_size,
        "multi": b"B" * (modes.block_size * 3 + 5),
    }
    out: dict[str, bool] = {}
    for mode in ("CBC", "OFB", "CTR"):
        ok = True
        for label, m in msgs.items():
            iv, c = modes.Encrypt(mode, k, m)
            d = modes.Decrypt(mode, k, iv, c)
            ok = ok and (d == m)
        out[mode] = ok
    return out
