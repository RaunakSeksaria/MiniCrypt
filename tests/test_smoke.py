from pois.pa1_owf_prg import default_pa1_components
from pois.pa2_prf import ToyAESPRF
from pois.pa3_cpa import CPACipher
from pois.pa5_mac import CBCMAC
from pois.pa6_cca import EncryptThenMAC


def test_cpa_roundtrip():
    _, _, _ = default_pa1_components()
    c = CPACipher(ToyAESPRF.F)
    k = b"K" * 16
    r, ct = c.Enc(k, b"hello")
    assert c.Dec(k, r, ct) == b"hello"


def test_etm_roundtrip():
    c = CPACipher(ToyAESPRF.F)
    m = CBCMAC(ToyAESPRF.F)
    e = EncryptThenMAC(c, m)
    kE = b"E" * 16
    kM = b"M" * 16
    pair, tag = e.CCA_Enc(kE, kM, b"world")
    assert e.CCA_Dec(kE, kM, pair, tag) == b"world"


def test_etm_rejects_tamper():
    c = CPACipher(ToyAESPRF.F)
    m = CBCMAC(ToyAESPRF.F)
    e = EncryptThenMAC(c, m)
    kE = b"E" * 16
    kM = b"M" * 16
    pair, tag = e.CCA_Enc(kE, kM, b"world")
    r, ct = pair
    bad = (r, ct[:-1] + bytes([ct[-1] ^ 1]))
    assert e.CCA_Dec(kE, kM, bad, tag) is None
