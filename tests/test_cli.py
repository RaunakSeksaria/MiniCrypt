"""CLI smoke test: every crypto module's `__main__` demo runs to completion (exit 0).

Each module is executed as `python -m crypto.<name>` in a subprocess; a non-zero
exit or a timeout fails the test. This guards the standalone demos that the README
advertises, which the unit tests (importing functions directly) would not exercise.
"""
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

MODULES = [
    "owf_prg", "prf_ggm", "cpa_enc", "modes", "mac", "cca_enc", "merkle_damgard",
    "dlp_crhf", "birthday", "hmac", "diffie_hellman", "rsa", "miller_rabin", "crt",
    "signatures", "elgamal", "cca_pkc", "ot", "secure_and", "mpc",
]


class TestModuleCLIs(unittest.TestCase):
    pass


def _make_test(module):
    def test(self):
        proc = subprocess.run(
            [sys.executable, "-m", f"crypto.{module}"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(
            proc.returncode, 0,
            msg=f"`python -m crypto.{module}` exited {proc.returncode}\n{proc.stderr[-2000:]}",
        )
    test.__name__ = f"test_cli_{module}"
    return test


for _m in MODULES:
    setattr(TestModuleCLIs, f"test_cli_{_m}", _make_test(_m))


if __name__ == "__main__":
    unittest.main()
