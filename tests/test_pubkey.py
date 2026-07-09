"""Public-key primitives: RSA, ElGamal, and RSA-FDH signatures."""
import unittest

from crypto.elgamal import ElGamal
from crypto.rsa import (
    pkcs15_decrypt,
    pkcs15_encrypt,
    rsa_decrypt,
    rsa_encrypt,
    rsa_keygen,
)
from crypto.signatures import DigitalSignature


class TestRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kp = rsa_keygen(bits=256)

    def test_textbook_roundtrip(self):
        m = 42
        c = rsa_encrypt(self.kp.n, self.kp.e, m)
        self.assertNotEqual(c, m)
        self.assertEqual(rsa_decrypt(self.kp.d, self.kp.n, c), m)

    def test_pkcs15_roundtrip(self):
        msg = b"secret"
        c = pkcs15_encrypt(self.kp.n, self.kp.e, msg)
        self.assertEqual(pkcs15_decrypt(self.kp.d, self.kp.n, c), msg)


class TestElGamal(unittest.TestCase):
    def test_roundtrip(self):
        eg = ElGamal(bits=64)
        m = 12345
        c1, c2 = eg.encrypt(m)
        self.assertEqual(eg.decrypt(c1, c2), m)


class TestSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ds = DigitalSignature(bits=256)

    def test_valid_signature_verifies(self):
        msg = b"authentic message"
        self.assertTrue(self.ds.verify(msg, self.ds.sign(msg)))

    def test_wrong_message_rejected(self):
        sigma = self.ds.sign(b"authentic message")
        self.assertFalse(self.ds.verify(b"tampered message", sigma))

    def test_forged_signature_rejected(self):
        msg = b"authentic message"
        sigma = self.ds.sign(msg)
        self.assertFalse(self.ds.verify(msg, sigma + 1))


if __name__ == "__main__":
    unittest.main()
