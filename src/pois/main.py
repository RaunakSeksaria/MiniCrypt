from __future__ import annotations

import argparse

from .pa1_owf_prg import default_pa1_components, nist_like_tests
from .pa2_prf import GGMPRF, ToyAESPRF, prf_distinguishing_demo
from .pa3_cpa import CPACipher
from .pa5_mac import CBCMAC
from .pa6_cca import EncryptThenMAC
from .pa7_md import MerkleDamgard, xor_compress
from .pa8_dlp_hash import make_dlp_hash
from .pa10_hmac import HMAC
from .pa11_dh import gen_dh_params, dh_alice_step1, dh_alice_step2, dh_bob_step1, dh_bob_step2


def run_quick_demo() -> None:
    params, owf, prg = default_pa1_components()
    seed = b"\x01" * 16
    out = prg.eval_full(seed, 256)
    print("PA1 PRG tests:", nist_like_tests(out))

    ggm = GGMPRF(prg)
    k = b"\x02" * 16
    print("PA2 GGM PRF sample:", ggm.F(k, "1011").hex())
    print("PA2 distinguisher:", prf_distinguishing_demo(ToyAESPRF.F))

    cpa = CPACipher(ToyAESPRF.F)
    r, c = cpa.Enc(k, b"hello pois")
    print("PA3 decrypt ok:", cpa.Dec(k, r, c) == b"hello pois")

    mac = CBCMAC(ToyAESPRF.F)
    etm = EncryptThenMAC(cpa, mac)
    kp = b"\x03" * 16
    (rr, cc), t = etm.CCA_Enc(k, kp, b"integrity")
    print("PA6 decrypt ok:", etm.CCA_Dec(k, kp, (rr, cc), t) == b"integrity")

    md = MerkleDamgard(xor_compress, iv=b"\x00" * 4, block_size=8, out_size=4)
    print("PA7 toy hash:", md.hash(b"abc").hex())

    dlp_hash = make_dlp_hash(params)
    print("PA8 dlp hash:", dlp_hash.hash(b"abc").hex())

    hm = HMAC(dlp_hash.hash)
    tag = hm.tag(b"k" * 16, b"msg")
    print("PA10 hmac verify:", hm.verify(b"k" * 16, b"msg", tag))

    dh = gen_dh_params(32)
    a, A = dh_alice_step1(dh)
    b, B = dh_bob_step1(dh)
    print("PA11 DH shared key equal:", dh_alice_step2(dh, a, B) == dh_bob_step2(dh, b, A))


def main() -> None:
    parser = argparse.ArgumentParser(description="POIS assignment demo runner")
    parser.add_argument("--quick", action="store_true", help="Run quick smoke demo")
    args = parser.parse_args()
    if args.quick:
        run_quick_demo()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
