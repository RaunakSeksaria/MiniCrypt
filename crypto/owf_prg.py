"""
crypto/owf_prg.py — One-Way Functions & Pseudorandom Generators

Implements:
  1. OWF (three concrete instantiations):
     - DLP-based: f(x) = g^x mod p
     - Factoring-based: f(p, q) = p * q
     - AES-based (Davies-Meyer): f(k) = AES_k(0^128) ⊕ k
  2. PRG from OWF (HILL / iterative hard-core-bit construction):
     G(x0) = b(x0) ‖ b(x1) ‖ ... ‖ b(x_l)  where x_{i+1} = f(x_i)
     b is the Goldreich-Levin hard-core predicate.
  3. PRG from AES (practical variant):
     G(s) = AES_s(0) ‖ AES_s(1)  (length-doubling)
  4. Backward direction: PRG ⇒ OWF (f(s) = G(s))
  5. NIST SP 800-22 statistical tests (monobit, runs, serial)

Dependencies: crypto.utils, crypto.aes, crypto.miller_rabin
Used by: (GGM PRF)

Bidirectional: OWF ⇔ PRG
  Forward:  OWF ⇒ PRG via HILL hard-core-bit construction
  Backward: PRG ⇒ OWF since f(s) = G(s) is hard to invert
"""

import math
import time

from crypto.aes import BLOCK_SIZE, aes_encrypt_block, aes_owf
from crypto.miller_rabin import find_generator, gen_safe_prime
from crypto.utils import (
    bits_to_bytes,
    bytes_to_bits,
    int_to_bytes,
    mod_exp,
    random_bytes,
    random_int,
    to_hex,
)

# ---------------------------------------------------------------------------
# One-Way Functions
# ---------------------------------------------------------------------------

class DLP_OWF:
    """
    DLP-based One-Way Function: f(x) = g^x mod p
    in a prime-order subgroup of Z*_p (safe prime p = 2q+1).
    """

    def __init__(self, bits: int = 64):
        """Initialize with a safe prime of given bit length."""
        self.p, self.q = gen_safe_prime(bits)
        self.g = find_generator(self.p, self.q)
        self.bits = bits

    def evaluate(self, x: int) -> int:
        """Compute f(x) = g^x mod p."""
        return mod_exp(self.g, x % self.q, self.p)

    def verify_hardness(self, trials: int = 100) -> dict:
        """
        Demonstrate that random inversion fails.
        For each trial, compute y = f(x) and try to find x' such that f(x') = y
        by guessing random x'. Report success rate (should be ~0).
        """
        successes = 0
        for _ in range(trials):
            x = random_int(1, self.q - 1)
            y = self.evaluate(x)
            # Try random inversion
            for _ in range(100):
                x_guess = random_int(1, self.q - 1)
                if self.evaluate(x_guess) == y:
                    successes += 1
                    break
        return {
            'trials': trials,
            'inversions': successes,
            'success_rate': successes / trials,
        }

    def __repr__(self):
        return f"DLP_OWF(bits={self.bits}, p={self.p}, g={self.g})"


class AES_OWF:
    """
    AES-based compression OWF (Davies-Meyer):
    f(k) = AES_k(0^128) ⊕ k
    """

    def evaluate(self, k: bytes) -> bytes:
        """Compute f(k) = AES_k(0^128) ⊕ k."""
        if len(k) != 16:
            raise ValueError("AES OWF requires 16-byte key")
        return aes_owf(k)

    def verify_hardness(self, trials: int = 50) -> dict:
        """Demonstrate inversion is hard by random guessing."""
        successes = 0
        for _ in range(trials):
            k = random_bytes(16)
            y = self.evaluate(k)
            for _ in range(100):
                k_guess = random_bytes(16)
                if self.evaluate(k_guess) == y:
                    successes += 1
                    break
        return {
            'trials': trials,
            'inversions': successes,
            'success_rate': successes / trials,
        }


class FactoringOWF:
    """
    Factoring-based OWF: f(p, q) = p * q
    Given the product N, recovering p and q is computationally hard.
    """

    def evaluate(self, p: int, q: int) -> int:
        """Compute f(p, q) = p * q."""
        return p * q

    def verify_hardness(self, bits: int = 32) -> dict:
        """Show that factoring a small product takes effort."""
        from crypto.miller_rabin import gen_prime
        p, _ = gen_prime(bits)
        q, _ = gen_prime(bits)
        n = p * q

        start = time.time()
        # Try trial division up to sqrt(n)
        found = None
        limit = min(int(n ** 0.5) + 1, 10_000_000)
        for i in range(2, limit):
            if n % i == 0:
                found = (i, n // i)
                break
        elapsed = time.time() - start

        return {
            'n': n,
            'bits': bits * 2,
            'factored': found is not None,
            'factors': found,
            'time_sec': elapsed,
            'search_limit': limit,
        }


# ---------------------------------------------------------------------------
# Hard-Core Predicate (Goldreich-Levin)
# ---------------------------------------------------------------------------

def goldreich_levin_bit(x: int, r: int, n_bits: int) -> int:
    """
    Goldreich-Levin hard-core predicate:
    b(x) = ⟨x, r⟩ mod 2 = XOR of bits where both x and r have a 1.

    Args:
        x: The input value.
        r: A public random string (same bit length as x).
        n_bits: Number of bits to consider.

    Returns:
        0 or 1.
    """
    # Inner product mod 2
    val = x & r  # bitwise AND
    # Count the number of 1 bits (popcount) mod 2
    result = 0
    while val:
        result ^= (val & 1)
        val >>= 1
    return result


# ---------------------------------------------------------------------------
# PRG from OWF (HILL Construction — iterative hard-core-bit)
# ---------------------------------------------------------------------------

class PRG_from_OWF:
    """
    PRG constructed from a OWF using the iterative hard-core-bit method.

    G(x_0) = b(x_0) ‖ b(x_1) ‖ ... ‖ b(x_ℓ)
    where x_{i+1} = f(x_i) and b is the Goldreich-Levin predicate.

    This expands an n-bit seed to (n + ℓ) pseudorandom bits.
    """

    def __init__(self, owf: any = None, bits: int = 64):
        if owf is None:
            owf = DLP_OWF(bits)
        self.owf = owf
        # Use q.bit_length() for DLP, or fixed 128 for AES
        self.n_bits = getattr(owf, 'q', type('obj', (object,), {'bit_length': lambda: 128})).bit_length()
        # Public random string for Goldreich-Levin
        self.r = random_int(1, (1 << self.n_bits) - 1)
        self.current_state = None

    def generate(self, seed: any, output_bits: int) -> list:
        bits = []
        # Handle seed conversion: int for DLP, bytes for AES
        if isinstance(seed, int):
            x = seed % getattr(self.owf, 'q', (1 << 128))
        else:
            x = int.from_bytes(seed, 'big')

        for _ in range(output_bits):
            # Extract one hard-core bit
            b = goldreich_levin_bit(x, self.r, self.n_bits)
            bits.append(b)
            # Iterate the OWF
            if isinstance(self.owf, DLP_OWF):
                x = self.owf.evaluate(x)
            else:
                # AES OWF expects bytes
                x_bytes = x.to_bytes(16, 'big')
                res_bytes = self.owf.evaluate(x_bytes)
                x = int.from_bytes(res_bytes, 'big')

        return bits

    def generate_bytes(self, seed: int, num_bytes: int) -> bytes:
        """Generate pseudorandom bytes from a seed."""
        bits = self.generate(seed, num_bytes * 8)
        return bits_to_bytes(bits)

    def seed(self, s: int):
        """Set/validate a seed value."""
        return s % self.owf.q

    def next_bits(self, seed: int, n: int) -> list:
        """Interface method: generate n bits from seed."""
        return self.generate(seed, n)


# ---------------------------------------------------------------------------
# PRG from AES (Practical Variant)
# ---------------------------------------------------------------------------

class PRG_from_AES:
    """
    Practical PRG using AES as a PRF:
    G(s) = AES_s(0) ‖ AES_s(1) ‖ AES_s(2) ‖ ...

    This is a length-doubling PRG (or more, depending on output length).
    Each AES call produces 16 bytes of pseudorandom output.
    """

    def __init__(self):
        self.block_size = BLOCK_SIZE  # 16 bytes
        self.current_seed = None
        self.counter = 0

    def generate(self, seed: bytes, output_bytes: int) -> bytes:
        """
        Generate pseudorandom bytes from a 16-byte seed.

        Args:
            seed: 16-byte seed (used as AES key).
            output_bytes: Number of output bytes desired.

        Returns:
            Pseudorandom byte string.
        """
        if len(seed) != 16:
            raise ValueError("PRG_from_AES requires 16-byte seed")

        result = bytearray()
        counter = 0
        while len(result) < output_bytes:
            # Use counter as plaintext block
            ctr_block = int_to_bytes(counter, 16)
            result.extend(aes_encrypt_block(ctr_block, seed))
            counter += 1

        return bytes(result[:output_bytes])

    def length_doubling(self, seed: bytes) -> bytes:
        """
        Length-doubling PRG: G(s) = F_s(0) ‖ F_s(1)
        Maps 16 bytes → 32 bytes.
        """
        if len(seed) != 16:
            raise ValueError("Seed must be 16 bytes")
        left = aes_encrypt_block(b'\x00' * 16, seed)
        right = aes_encrypt_block(b'\x00' * 15 + b'\x01', seed)
        return left + right

    def G0(self, seed: bytes) -> bytes:
        """Left half of length-doubling PRG: G_0(s)."""
        return self.length_doubling(seed)[:16]

    def G1(self, seed: bytes) -> bytes:
        """Right half of length-doubling PRG: G_1(s)."""
        return self.length_doubling(seed)[16:]

    def seed(self, s: bytes) -> bytes:
        """Validate seed."""
        if len(s) != 16:
            raise ValueError("Seed must be 16 bytes")
        return s

    def next_bits(self, seed: bytes, n: int) -> list:
        """Generate n pseudorandom bits from seed."""
        num_bytes = (n + 7) // 8
        output = self.generate(seed, num_bytes)
        return bytes_to_bits(output)[:n]


# ---------------------------------------------------------------------------
# b: Backward Direction (PRG ⇒ OWF)
# ---------------------------------------------------------------------------

def demonstrate_prg_inversion_v2(prg, trials: int = 50):
    """
    Demonstrate that f(s) = G(s) is a One-Way Function.

    WRITTEN ARGUMENT (Requirement 3):
    Proof by Contradiction:
    1. Suppose f(s) = G(s) is NOT a One-Way Function.
    2. Then there exists a PPT adversary A that, given y = G(s),
       can find s' such that G(s') = y with non-negligible probability.
    3. If such an A exists, we can build a distinguisher D for the PRG:
       - D receives a challenge string Z.
       - D runs A(Z) to get a candidate seed s'.
       - D checks if G(s') == Z.
       - If yes, D outputs 1 (predicting Z is pseudorandom).
       - If no, D outputs 0 (predicting Z is truly random).
    4. Since G is a secure PRG, no such distinguisher D can exist.
    5. Therefore, no such adversary A can exist, and f(s) = G(s) is a OWF.
    """
    sample_guesses = []
    successes = 0
    for i in range(trials):
        s = random_bytes(16)
        gs = prg.length_doubling(s)

        # Try to invert: guess random seeds
        for _ in range(200):
            s_guess = random_bytes(16)
            if i == 0 and len(sample_guesses) < 3:
                sample_guesses.append(to_hex(s_guess))
            if prg.length_doubling(s_guess) == gs:
                successes += 1
                break

    return {
        'trials': trials,
        'inversions': successes,
        'sample_guesses': sample_guesses,
        'conclusion': 'PRG output cannot be inverted → PRG is a OWF'
    }


# ---------------------------------------------------------------------------
# NIST SP 800-22 Statistical Tests
# ---------------------------------------------------------------------------

def frequency_test(bits: list) -> dict:
    """
    NIST SP 800-22 Frequency (Monobit) Test.
    Tests whether the number of 1s and 0s are approximately equal.
    """
    n = len(bits)
    if n == 0:
        return {'pass': False, 'p_value': 0.0}

    # Sum: convert 0→-1, 1→+1
    s = sum(2 * b - 1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)

    # p-value using complementary error function
    p_value = math.erfc(s_obs / math.sqrt(2))

    return {
        'test': 'frequency',
        'n': n,
        'sum': s,
        'statistic': s_obs,
        'p_value': p_value,
        'pass': p_value >= 0.01,
    }


def runs_test(bits: list) -> dict:
    """
    NIST SP 800-22 Runs Test.
    Tests whether the number of runs (consecutive identical bits) is as expected.
    """
    n = len(bits)
    if n == 0:
        return {'pass': False, 'p_value': 0.0}

    # Pre-test: check proportion of ones
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return {
            'test': 'runs',
            'pass': False,
            'p_value': 0.0,
            'reason': 'Failed frequency pre-test',
        }

    # Count runs
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1

    # Expected runs
    expected = 2 * n * pi * (1 - pi)
    # Variance
    variance = expected * (1 - 2 * pi * (1 - pi))
    if variance <= 0:
        return {'test': 'runs', 'pass': False, 'p_value': 0.0}

    p_value = math.erfc(abs(runs - expected - 1) / math.sqrt(2 * variance))

    return {
        'test': 'runs',
        'n': n,
        'runs': runs,
        'expected': expected,
        'p_value': p_value,
        'pass': p_value >= 0.01,
    }


def serial_test(bits: list, m: int = 2) -> dict:
    """
    NIST SP 800-22 Serial Test (simplified).
    Tests uniformity of m-bit patterns.
    """
    n = len(bits)
    if n < m:
        return {'pass': False, 'p_value': 0.0}

    def count_patterns(seq, pattern_len):
        counts = {}
        for i in range(len(seq) - pattern_len + 1):
            pattern = tuple(seq[i:i + pattern_len])
            counts[pattern] = counts.get(pattern, 0) + 1
        return counts

    # Augment sequence (wrap around)
    augmented = bits + bits[:m - 1]

    # Compute psi-squared statistics
    def psi_sq(pattern_len):
        counts = count_patterns(augmented, pattern_len)
        total = len(augmented) - pattern_len + 1
        return (2 ** pattern_len / total) * sum(c ** 2 for c in counts.values()) - total

    psi_m = psi_sq(m)
    psi_m1 = psi_sq(m - 1) if m > 1 else 0
    psi_m2 = psi_sq(m - 2) if m > 2 else 0

    delta1 = psi_m - psi_m1
    delta2 = psi_m - 2 * psi_m1 + psi_m2

    # Approximate p-values using chi-squared distribution
    # Degrees of freedom: 2^{m-1} for delta1, 2^{m-2} for delta2
    # Simplified: use ratio to expected as indicator
    expected_variance = 2 ** (m - 1)
    p_value = math.exp(-delta1 / (2 * max(expected_variance, 1)))

    return {
        'test': 'serial',
        'n': n,
        'm': m,
        'delta1': delta1,
        'delta2': delta2,
        'p_value': min(p_value, 1.0),
        'pass': p_value >= 0.01,
    }


def run_statistical_tests(bits: list) -> list:
    """Run all three NIST tests on a bit sequence."""
    return [
        frequency_test(bits),
        runs_test(bits),
        serial_test(bits, m=2),
    ]


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("One-Way Functions & Pseudorandom Generators")
    print("=" * 60)

    # --- AES-based PRG (practical) ---
    print("\n--- AES-Based PRG (Practical) ---")
    prg_aes = PRG_from_AES()
    seed_aes = random_bytes(16)
    print(f"Seed: {to_hex(seed_aes)}")

    output = prg_aes.generate(seed_aes, 32)
    print(f"PRG output (32 bytes): {to_hex(output)}")

    ld = prg_aes.length_doubling(seed_aes)
    print(f"Length-doubling G(s): {to_hex(ld)} ({len(ld)} bytes from 16-byte seed)")

    # Statistical tests on PRG output
    bits = prg_aes.next_bits(seed_aes, 1000)
    print("\nStatistical tests on 1000 PRG bits:")
    for result in run_statistical_tests(bits):
        status = "PASS" if result['pass'] else "FAIL"
        print(f"  {result['test']}: {status} (p={result['p_value']:.4f})")

    # --- DLP-based OWF ---
    print("\n--- DLP-Based OWF ---")
    dlp = DLP_OWF(bits=32)
    x = random_int(1, dlp.q - 1)
    y = dlp.evaluate(x)
    print(f"p = {dlp.p}, g = {dlp.g}, q = {dlp.q}")
    print(f"f({x}) = g^x mod p = {y}")
    hardness = dlp.verify_hardness(trials=20)
    print(f"Inversion attempts: {hardness['inversions']}/{hardness['trials']} "
          f"(rate: {hardness['success_rate']:.2f})")

    # --- DLP-based PRG ---
    print("\n--- DLP-Based PRG (HILL Construction) ---")
    prg_dlp = PRG_from_OWF(dlp)
    seed_dlp = random_int(1, dlp.q - 1)
    prg_bits = prg_dlp.generate(seed_dlp, 100)
    print(f"Seed: {seed_dlp}")
    print(f"First 50 PRG bits: {''.join(map(str, prg_bits[:50]))}")
    print(f"Bit ratio (1s): {sum(prg_bits) / len(prg_bits):.2f}")

    # --- Backward: PRG ⇒ OWF ---
    print("\n--- Backward Direction: PRG ⇒ OWF ---")
    inv_result = demonstrate_prg_inversion_v2(prg_aes, trials=20)
    print(f"Inversion attempts: {inv_result['inversions']}/{inv_result['trials']}")
    print(f"Conclusion: {inv_result['conclusion']}")

    # --- AES OWF ---
    print("\n--- AES-Based OWF (Davies-Meyer) ---")
    aes_f = AES_OWF()
    k = random_bytes(16)
    y = aes_f.evaluate(k)
    print(f"f({to_hex(k)}) = {to_hex(y)}")
