"""Symmetric primitives: CPA/CCA encryption, MAC, HMAC, and block-cipher modes."""
import unittest

from crypto.cca_enc import CCAEncryption
from crypto.cpa_enc import CPAEncryption
from crypto.hmac import HMAC
from crypto.mac import MAC
from crypto.modes import (
    cbc_decrypt,
    cbc_encrypt,
    ctr_decrypt,
    ctr_encrypt,
    ofb_decrypt,
    ofb_encrypt,
)
from crypto.utils import random_bytes


class TestCPAEncryption(unittest.TestCase):
    def test_roundtrip(self):
        enc = CPAEncryption()
        key = random_bytes(16)
        msg = b"a message spanning multiple AES blocks for good measure"
        r, ct = enc.encrypt(key, msg)
        self.assertEqual(enc.decrypt(key, r, ct), msg)

    def test_randomized_ciphertexts_differ(self):
        enc = CPAEncryption()
        key = random_bytes(16)
        _, ct1 = enc.encrypt(key, b"same message")
        _, ct2 = enc.encrypt(key, b"same message")
        self.assertNotEqual(ct1, ct2)  # fresh nonce each call


class TestCCAEncryption(unittest.TestCase):
    def setUp(self):
        self.cca = CCAEncryption()
        self.ke, self.km = random_bytes(16), random_bytes(16)

    def test_roundtrip(self):
        msg = b"encrypt-then-MAC"
        r, ct, tag = self.cca.encrypt(self.ke, self.km, msg)
        self.assertEqual(self.cca.decrypt(self.ke, self.km, r, ct, tag), msg)

    def test_tampered_ciphertext_rejected(self):
        r, ct, tag = self.cca.encrypt(self.ke, self.km, b"encrypt-then-MAC")
        flipped = bytes([ct[0] ^ 1]) + ct[1:]
        self.assertIsNone(self.cca.decrypt(self.ke, self.km, r, flipped, tag))


class TestMAC(unittest.TestCase):
    def test_valid_tag_verifies_and_forgery_rejected(self):
        mac = MAC(mode="cbc")
        key = random_bytes(16)
        msg = b"authenticate me"
        tag = mac.Mac(key, msg)
        self.assertTrue(mac.Vrfy(key, msg, tag))
        self.assertFalse(mac.Vrfy(key, b"different message", tag))


class TestHMAC(unittest.TestCase):
    def test_valid_tag_verifies_and_forgery_rejected(self):
        h = HMAC(bits=64)
        key = random_bytes(16)
        msg = b"authenticate me"
        tag = h.mac(key, msg)
        self.assertTrue(h.verify(key, msg, tag))
        self.assertFalse(h.verify(key, b"different message", tag))


class TestModes(unittest.TestCase):
    def setUp(self):
        self.key = random_bytes(16)
        self.iv = random_bytes(16)
        self.msg = b"mode of operation round-trip test message"

    def test_cbc_roundtrip(self):
        self.assertEqual(cbc_decrypt(self.key, self.iv, cbc_encrypt(self.key, self.iv, self.msg)), self.msg)

    def test_ofb_roundtrip(self):
        self.assertEqual(ofb_decrypt(self.key, self.iv, ofb_encrypt(self.key, self.iv, self.msg)), self.msg)

    def test_ctr_roundtrip(self):
        nonce, ct = ctr_encrypt(self.key, self.msg)
        self.assertEqual(ctr_decrypt(self.key, nonce, ct), self.msg)


if __name__ == "__main__":
    unittest.main()
