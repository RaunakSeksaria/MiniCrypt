"""Miller-Rabin primality: primes accepted, composites and Carmichael numbers rejected."""
import unittest

from crypto.miller_rabin import is_prime, miller_rabin


class TestMillerRabin(unittest.TestCase):
    PRIMES = [2, 3, 5, 7, 97, 7919, 104729, 1000003]
    COMPOSITES = [1, 4, 100, 104730, 999983 * 3]
    CARMICHAEL = [561, 1105, 1729, 2465, 41041]  # fool the Fermat test, not Miller-Rabin

    def test_primes_accepted(self):
        for p in self.PRIMES:
            self.assertTrue(miller_rabin(p), f"{p} should be prime")

    def test_composites_rejected(self):
        for n in self.COMPOSITES:
            self.assertFalse(miller_rabin(n), f"{n} should be composite")

    def test_carmichael_numbers_rejected(self):
        for n in self.CARMICHAEL:
            self.assertFalse(is_prime(n), f"Carmichael {n} must be caught by Miller-Rabin")


if __name__ == "__main__":
    unittest.main()
