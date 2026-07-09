"""AES-128 correctness against the FIPS-197 known-answer vector."""
import unittest

from crypto.aes import aes_decrypt_block, aes_encrypt_block


class TestAESKnownAnswer(unittest.TestCase):
    # FIPS-197, Appendix C.1 (AES-128)
    KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
    CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_encrypt_matches_fips197_vector(self):
        self.assertEqual(aes_encrypt_block(self.PLAINTEXT, self.KEY), self.CIPHERTEXT)

    def test_decrypt_matches_fips197_vector(self):
        self.assertEqual(aes_decrypt_block(self.CIPHERTEXT, self.KEY), self.PLAINTEXT)

    def test_encrypt_decrypt_roundtrip(self):
        import os
        key = os.urandom(16)
        block = os.urandom(16)
        self.assertEqual(aes_decrypt_block(aes_encrypt_block(block, key), key), block)


if __name__ == "__main__":
    unittest.main()
