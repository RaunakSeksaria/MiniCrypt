"""Reduction-chain primitives: PRG and PRF are deterministic and seed-sensitive."""
import unittest

from crypto.owf_prg import PRG_from_AES
from crypto.prf_ggm import PRF
from crypto.utils import random_bytes


class TestPRG(unittest.TestCase):
    def test_deterministic_and_seed_sensitive(self):
        prg = PRG_from_AES()
        seed = random_bytes(16)
        out1 = prg.generate(seed, 32)
        out2 = prg.generate(seed, 32)
        self.assertEqual(out1, out2)          # deterministic in the seed
        self.assertEqual(len(out1), 32)       # produces requested length
        self.assertNotEqual(prg.generate(random_bytes(16), 32), out1)  # seed-sensitive


class TestPRF(unittest.TestCase):
    def _check(self, mode):
        prf = PRF(mode=mode)
        key = random_bytes(16)
        x = random_bytes(16)
        self.assertEqual(prf.evaluate(key, x), prf.evaluate(key, x))          # deterministic
        self.assertNotEqual(prf.evaluate(key, x), prf.evaluate(key, bytes(16)))  # input-sensitive
        self.assertNotEqual(prf.evaluate(random_bytes(16), x), prf.evaluate(key, x))  # key-sensitive

    def test_aes_prf(self):
        self._check("aes")

    def test_ggm_prf(self):
        self._check("ggm")


if __name__ == "__main__":
    unittest.main()
