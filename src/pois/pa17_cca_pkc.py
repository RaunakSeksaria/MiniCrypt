from __future__ import annotations

from dataclasses import dataclass

from .pa15_signatures import RSASignatureScheme


@dataclass
class CCAPublicKeyEncryption:
    enc_fn: callable
    dec_fn: callable
    sig_scheme: RSASignatureScheme

    def Enc(self, pk_enc, sk_sign, m: int):
        ce = self.enc_fn(pk_enc, m)
        ce_bytes = repr(ce).encode()
        sigma = self.sig_scheme.Sign(sk_sign, ce_bytes)
        return ce, sigma

    def Dec(self, sk_enc, vk_sign, ce, sigma):
        ce_bytes = repr(ce).encode()
        if not self.sig_scheme.Verify(vk_sign, ce_bytes, sigma):
            return None
        if isinstance(ce, tuple):
            return self.dec_fn(sk_enc, ce[0], ce[1])
        return self.dec_fn(sk_enc, ce)


def ind_cca2_pkc_demo(scheme: CCAPublicKeyEncryption, pk_enc, sk_enc, sk_sign, vk_sign, m: int) -> dict[str, bool]:
    ce, sigma = scheme.Enc(pk_enc, sk_sign, m)
    if isinstance(ce, tuple):
        tampered = (ce[0], (ce[1] + 1) % pk_enc.params.p)
    else:
        tampered = ce + 1
    out = scheme.Dec(sk_enc, vk_sign, tampered, sigma)
    clean = scheme.Dec(sk_enc, vk_sign, ce, sigma)
    return {
        "tamper_rejected": out is None,
        "untampered_decrypts": clean is not None,
    }
