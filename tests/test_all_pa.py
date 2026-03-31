from pois.pa1_owf_prg import default_pa1_components, nist_like_tests, prg_is_owf_demo
from pois.pa2_prf import GGMPRF, ToyAESPRF, prg_from_prf, prf_distinguishing_demo
from pois.pa3_cpa import CPACipher, BrokenDeterministicCPA, deterministic_reuse_attack
from pois.pa4_modes import Modes, cbc_iv_reuse_leak_demo, ofb_keystream_reuse_xor_demo, roundtrip_lengths_demo
from pois.pa5_mac import PRFMAC, CBCMAC, hmac_stub, euf_cma_game
from pois.pa6_cca import EncryptThenMAC, ind_cca2_demo
from pois.pa7_md import MerkleDamgard, xor_compress, collision_propagation_demo
from pois.pa8_dlp_hash import make_dlp_hash, tiny_collision_search
from pois.pa9_birthday import birthday_attack, empirical_collision_trials, theoretical_collision_probability
from pois.pa10_hmac import HMAC, EncryptThenHMAC, constant_time_compare, compare_timing_demo, mac_to_crhf_demo
from pois.pa11_dh import gen_dh_params, dh_exchange, mitm_demo, cdh_bruteforce_demo
from pois.pa12_rsa import (
    rsa_keygen,
    rsa_enc,
    rsa_dec,
    pkcs15_enc,
    pkcs15_dec,
    textbook_determinism_demo,
    pkcs15_randomized_demo,
)
from pois.pa13_miller_rabin import carmichael_demo, prime_generation_benchmark
from pois.pa14_crt import crt, rsa_dec_crt, hastad_attack, rsa_crt_speedup_demo
from pois.pa15_signatures import RSASignatureScheme, euf_cma_signature_demo
from pois.pa16_elgamal import elgamal_keygen, elgamal_enc, elgamal_dec, malleability_attack
from pois.pa17_cca_pkc import CCAPublicKeyEncryption, ind_cca2_pkc_demo
from pois.pa18_ot import ot_correctness_demo, ot_trial
from pois.pa19_secure_gates import secure_and, secure_xor, secure_not, truth_table
from pois.pa20_mpc import secure_millionaire, secure_equality, secure_addition


def _toy_hash(data: bytes) -> bytes:
    acc = 0
    for b in data:
        acc = ((acc * 131) ^ b) & ((1 << 128) - 1)
    return acc.to_bytes(16, "big")


def test_pa1_to_pa10_core():
    params, owf, prg = default_pa1_components()
    y = owf.evaluate(7)
    assert isinstance(y, int)
    out = prg.eval_full(b"\x01" * 16, 128)
    tests = nist_like_tests(out)
    assert set(tests.keys()) == {"monobit", "runs", "serial"}
    assert prg_is_owf_demo(prg, b"\x02" * 16)

    ggm = GGMPRF(prg)
    y1 = ggm.F(b"\x03" * 16, "1011")
    y2 = ggm.F(b"\x03" * 16, "1011")
    assert y1 == y2
    prg_out = prg_from_prf(ToyAESPRF.F, b"\x04" * 16)
    assert len(prg_out) == 32
    stats = prf_distinguishing_demo(ToyAESPRF.F)
    assert 0 <= stats["prf_one_ratio"] <= 1

    cpa = CPACipher(ToyAESPRF.F)
    k = b"K" * 16
    r, c = cpa.Enc(k, b"hello world")
    assert cpa.Dec(k, r, c) == b"hello world"
    broken = BrokenDeterministicCPA(ToyAESPRF.F)
    assert deterministic_reuse_attack(broken, k, b"same")

    modes = Modes(ToyAESPRF.F, ToyAESPRF.D)
    rt = roundtrip_lengths_demo(modes, k)
    assert all(rt.values())
    iv = b"\x00" * 16
    assert cbc_iv_reuse_leak_demo(modes, k, iv, b"A" * 16 + b"x", b"A" * 16 + b"y")
    x1, x2 = ofb_keystream_reuse_xor_demo(modes, k, iv, b"msg-1", b"msg-2")
    assert x1 == x2

    prf_mac = PRFMAC(ToyAESPRF.F)
    tag = prf_mac.Mac(k, b"M" * 16)
    assert prf_mac.Vrfy(k, b"M" * 16, tag)
    cbc_mac = CBCMAC(ToyAESPRF.F)
    tag2 = cbc_mac.Mac(k, b"variable")
    assert cbc_mac.Vrfy(k, b"variable", tag2)
    assert isinstance(hmac_stub(k, b"m"), bytes)
    game = euf_cma_game(cbc_mac, k)
    assert game["new_message"]

    etm = EncryptThenMAC(cpa, cbc_mac)
    pair, t = etm.CCA_Enc(k, b"M" * 16, b"secure")
    assert etm.CCA_Dec(k, b"M" * 16, pair, t) == b"secure"
    cca = ind_cca2_demo(etm, k, b"M" * 16, b"a", b"b", 0)
    assert cca["tamper_rejected"]

    md = MerkleDamgard(xor_compress, iv=b"\x00" * 4, block_size=8, out_size=4)
    assert collision_propagation_demo(md, b"\x01" * 8, b"\x01" * 8)

    dlp_hash = make_dlp_hash(params)
    h1 = dlp_hash.hash(b"abc")
    h2 = dlp_hash.hash(b"abcd")
    assert h1 != h2
    coll = tiny_collision_search(params, out_bits=8, max_iters=5000)
    assert coll is not None

    bres = birthday_attack(lambda m: _toy_hash(m), n_bits=8, max_iters=2000)
    assert bres is not None
    trials = empirical_collision_trials(lambda m: _toy_hash(m), 8, trials=5, max_iters=2000)
    assert len(trials) == 5
    p = theoretical_collision_probability(32, 8)
    assert 0 <= p <= 1

    hm = HMAC(_toy_hash)
    ht = hm.tag(k, b"msg")
    assert hm.verify(k, b"msg", ht)
    assert constant_time_compare(ht, ht)
    td = compare_timing_demo(ht, b"\x00" + ht[1:], ht[:-1] + b"\x00", rounds=100)
    assert "early_mismatch_s" in td

    # PA#10 backward direction: MAC => CRHF
    mac_crhf = mac_to_crhf_demo(hm, k)
    assert mac_crhf["distinct_inputs_yield_distinct_outputs"]
    assert mac_crhf["crhf_from_mac"]

    eth = EncryptThenHMAC(cpa, hm)
    pair2, tagh = eth.Enc(k, b"M" * 16, b"payload")
    assert eth.Dec(k, b"M" * 16, pair2, tagh) == b"payload"


def test_pa11_to_pa20_core():
    params = gen_dh_params(20)
    A, B, KA, KB = dh_exchange(params)
    assert KA == KB
    assert cdh_bruteforce_demo(params, A, B, max_exp=params.q) == KA
    m = mitm_demo(params)
    assert m[0] == m[2] and m[1] == m[3]

    pk, sk = rsa_keygen(128, e=17)
    msg = 12345
    c = rsa_enc(pk, msg)
    assert rsa_dec(sk, c) == msg
    assert rsa_dec_crt(sk, c) == msg
    assert textbook_determinism_demo(pk, msg)
    assert pkcs15_randomized_demo(pk, b"hi")
    c2 = pkcs15_enc(pk, b"hello")
    assert pkcs15_dec(sk, c2) == b"hello"

    demo = carmichael_demo()
    assert demo["fermat_passes"] and demo["miller_rabin_rejects"]
    bench = prime_generation_benchmark(32, samples=2, k=10)
    assert bench["avg_candidates"] >= 1

    x = crt([2, 3, 2], [3, 5, 7])
    assert x % 3 == 2 and x % 5 == 3 and x % 7 == 2

    pks = [rsa_keygen(128, e=3)[0] for _ in range(3)]
    m_small = 42
    cs = [rsa_enc(ppk, m_small) for ppk in pks]
    recovered = hastad_attack(cs, [ppk.N for ppk in pks], e=3)
    assert recovered == m_small
    speed = rsa_crt_speedup_demo(sk, [c, c, c])
    assert speed["crt_seconds"] >= 0

    sig = RSASignatureScheme(_toy_hash)
    sigma = sig.Sign(sk, b"doc")
    assert sig.Verify(pk, b"doc", sigma)
    sig_game = euf_cma_signature_demo(sig, sk, pk, queries=5)
    assert sig_game["new_message"]

    epk, esk = elgamal_keygen(params)
    c1, c2 = elgamal_enc(epk, 7)
    dec = elgamal_dec(esk, c1, c2)
    assert dec == 7 % params.p
    mc1, mc2 = malleability_attack(c1, c2, params.p, factor=2)
    assert elgamal_dec(esk, mc1, mc2) == (2 * dec) % params.p

    cca = CCAPublicKeyEncryption(elgamal_enc, elgamal_dec, sig)
    ce, sg = cca.Enc(epk, sk, 9)
    assert cca.Dec(esk, pk, ce, sg) == 9 % params.p
    cca_demo = ind_cca2_pkc_demo(cca, epk, esk, sk, pk, 11)
    assert cca_demo["tamper_rejected"]

    assert ot_correctness_demo(params, trials=10)
    assert ot_trial(params, 1, 55, 77) == 77

    for a in (0, 1):
        for b in (0, 1):
            assert secure_and(params, a, b) == (a & b)
            assert secure_xor(a, b) == (a ^ b)
    assert secure_not(0) == 1 and secure_not(1) == 0
    tbl = truth_table(params)
    assert len(tbl) == 4

    assert secure_equality(params, 7, 7, n=4) == 1
    assert secure_equality(params, 7, 6, n=4) == 0
    assert secure_millionaire(params, 12, 7, n=4) == 1
    assert secure_millionaire(params, 7, 12, n=4) == 0
    assert secure_addition(params, 5, 9, n=4) == ((5 + 9) & 0xF)
