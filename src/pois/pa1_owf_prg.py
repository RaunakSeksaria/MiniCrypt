from __future__ import annotations

from dataclasses import dataclass

from .common import bits_from_bytes, bytes_to_int, int_to_bytes, monobit_test, runs_test, serial_test
from .pa13_miller_rabin import is_prime


def gen_safe_prime(bits: int = 32) -> tuple[int, int]:
    # Educational-size parameters for fast demos.
    candidate = (1 << (bits - 1)) | 1
    while True:
        q = candidate
        p = 2 * q + 1
        if is_prime(q, 20) and is_prime(p, 20):
            return p, q
        candidate += 2


def find_generator(p: int, q: int) -> int:
    for g in range(2, p - 1):
        if pow(g, 2, p) != 1 and pow(g, q, p) == 1:
            return g
    raise ValueError("no generator found")


@dataclass
class DLPParams:
    p: int
    q: int
    g: int


class DLPBasedOWF:
    def __init__(self, params: DLPParams):
        self.params = params

    def evaluate(self, x: int) -> int:
        return pow(self.params.g, x % self.params.q, self.params.p)

    def verify_hardness_demo(self, y: int, max_guess: int = 10000) -> bool:
        # Returns True when random brute-force fails within budget.
        for guess in range(max_guess):
            if self.evaluate(guess) == y:
                return False
        return True


class PRGFromOWF:
    def __init__(self, owf: DLPBasedOWF, n_bytes: int = 16):
        self.owf = owf
        self.n_bytes = n_bytes
        self.state = 1

    @staticmethod
    def hard_core_bit(x: int) -> int:
        return x & 1

    def seed(self, s: bytes) -> None:
        self.state = bytes_to_int(s) % self.owf.params.q

    def next_bits(self, n: int) -> bytes:
        bits: list[int] = []
        x = self.state
        while len(bits) < n:
            x = self.owf.evaluate(x)
            bits.append(self.hard_core_bit(x))
        self.state = x
        out = bytearray((n + 7) // 8)
        for i, b in enumerate(bits):
            out[i // 8] |= b << (7 - (i % 8))
        return bytes(out)

    def next_bytes(self, n_bytes: int) -> bytes:
        return self.next_bits(n_bytes * 8)[:n_bytes]

    def eval_full(self, seed: bytes, extra_bits: int = 128) -> bytes:
        self.seed(seed)
        return seed + self.next_bits(extra_bits)


def owf_from_prg(prg: PRGFromOWF, s: bytes, out_bits: int = 256) -> bytes:
    prg.seed(s)
    return prg.next_bits(out_bits)


def prg_is_owf_demo(prg: PRGFromOWF, seed: bytes, budget: int = 1024) -> bool:
    """Tiny inversion-failure demo for the backward PRG=>OWF direction."""
    y = owf_from_prg(prg, seed, 128)
    for i in range(budget):
        guess = int_to_bytes(i, len(seed))
        if owf_from_prg(prg, guess, 128) == y:
            return False
    return True


def nist_like_tests(data: bytes) -> dict[str, tuple[bool, float]]:
    bits = bits_from_bytes(data)
    return {
        "monobit": monobit_test(bits),
        "runs": runs_test(bits),
        "serial": serial_test(bits),
    }


def default_pa1_components() -> tuple[DLPParams, DLPBasedOWF, PRGFromOWF]:
    p, q = gen_safe_prime(20)
    params = DLPParams(p=p, q=q, g=find_generator(p, q))
    owf = DLPBasedOWF(params)
    prg = PRGFromOWF(owf)
    return params, owf, prg
