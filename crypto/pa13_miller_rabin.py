"""
crypto/pa13_miller_rabin.py — PA#13: Miller-Rabin Primality Testing

Implements:
  1. Miller-Rabin probabilistic primality test
  2. Prime generation (random sampling + testing)
  3. Safe prime generation (p = 2q+1)
  4. Carmichael number detection demo
  5. Performance benchmarking

Dependencies: crypto.utils (mod_exp, random_int, random_bits)
Used by: PA#11 (DH), PA#12 (RSA), PA#8 (DLP-CRHF)
"""

import time
from crypto.utils import mod_exp, random_int, random_bits


# ---------------------------------------------------------------------------
# Miller-Rabin Primality Test
# ---------------------------------------------------------------------------

def miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.

    Args:
        n: The odd integer > 2 to test.
        k: Number of rounds (error prob ≤ 4^{-k}).

    Returns:
        True if n is probably prime, False if definitely composite.
    """
    # Handle small cases
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 = 2^s * d with d odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # Perform k rounds of testing
    for _ in range(k):
        a = random_int(2, n - 2)
        x = mod_exp(a, d, n)

        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(s - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                composite = False
                break

        if composite:
            return False

    return True


def is_prime(n: int, k: int = 40) -> bool:
    """
    Check if n is (probably) prime. Convenience wrapper around miller_rabin.
    """
    return miller_rabin(n, k)


# ---------------------------------------------------------------------------
# Naive Fermat Primality Test (for Carmichael number demo)
# ---------------------------------------------------------------------------

def fermat_test(n: int, k: int = 20) -> bool:
    """
    Naive Fermat primality test: checks if a^{n-1} ≡ 1 (mod n) for k random bases.
    WARNING: This is fooled by Carmichael numbers. Use miller_rabin instead.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    for _ in range(k):
        a = random_int(2, n - 2)
        if mod_exp(a, n - 1, n) != 1:
            return False
    return True


# ---------------------------------------------------------------------------
# Prime Generation
# ---------------------------------------------------------------------------

def gen_prime(bits: int, k: int = 40) -> int:
    """
    Generate a random probable prime of the specified bit length.

    Args:
        bits: Desired bit length of the prime.
        k: Number of Miller-Rabin rounds.

    Returns:
        A probable prime integer of the given bit length.
    """
    while True:
        # Generate random odd number with the correct bit length
        candidate = random_bits(bits)
        candidate |= 1  # Make sure it's odd

        if miller_rabin(candidate, k):
            # Sanity check with extra rounds
            if miller_rabin(candidate, min(k, 20)):
                return candidate


def gen_safe_prime(bits: int, k: int = 40) -> tuple:
    """
    Generate a safe prime p = 2q + 1 where both p and q are prime.

    Args:
        bits: Desired bit length of p.
        k: Number of Miller-Rabin rounds.

    Returns:
        (p, q) where p = 2q + 1, both prime.
    """
    while True:
        # Generate candidate q
        q = gen_prime(bits - 1, k)
        p = 2 * q + 1
        if miller_rabin(p, k):
            return p, q


def find_generator(p: int, q: int) -> int:
    """
    Find a generator g of the prime-order subgroup of Z*_p of order q,
    where p = 2q + 1 is a safe prime.

    The subgroup of order q consists of quadratic residues mod p.
    A random element h in Z*_p has order p-1=2q if h ≠ ±1 mod p.
    Its square g = h^2 mod p has order q.
    """
    while True:
        h = random_int(2, p - 2)
        g = mod_exp(h, 2, p)
        if g != 1:
            return g


# ---------------------------------------------------------------------------
# Demos and Benchmarks
# ---------------------------------------------------------------------------

def carmichael_demo():
    """
    Demonstrate that n = 561 (smallest Carmichael number) passes the naive
    Fermat test but is correctly rejected by Miller-Rabin.
    """
    n = 561  # 561 = 3 × 11 × 17

    results = {
        'n': n,
        'factorization': '3 × 11 × 17',
        'fermat_results': [],
        'miller_rabin_results': [],
    }

    # Run Fermat test 10 times
    for _ in range(10):
        results['fermat_results'].append(fermat_test(n, k=20))

    # Run Miller-Rabin test 10 times
    for _ in range(10):
        results['miller_rabin_results'].append(miller_rabin(n, k=5))

    return results


def benchmark_prime_generation(bit_sizes=None):
    """
    Benchmark prime generation for various bit sizes.
    Reports average number of candidates tested and time taken.
    """
    if bit_sizes is None:
        bit_sizes = [64, 128, 256, 512]

    results = {}
    for bits in bit_sizes:
        candidates_tested = 0
        start = time.time()
        trials = 5

        for _ in range(trials):
            count = 0
            while True:
                count += 1
                candidate = random_bits(bits)
                candidate |= 1
                if miller_rabin(candidate, 40):
                    break
            candidates_tested += count

        elapsed = time.time() - start
        results[bits] = {
            'avg_candidates': candidates_tested / trials,
            'avg_time_sec': elapsed / trials,
            'theoretical_candidates': bits * 0.693,  # ~ ln(2^bits) / ln(2) ≈ bits * ln(2)
        }

    return results


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("PA#13: Miller-Rabin Primality Testing")
    print("=" * 60)

    # 1. Carmichael number demo
    print("\n--- Carmichael Number Demo (n = 561) ---")
    demo = carmichael_demo()
    print(f"n = {demo['n']} = {demo['factorization']}")
    print(f"Fermat says prime: {demo['fermat_results']}")
    print(f"Miller-Rabin says prime: {demo['miller_rabin_results']}")

    # 2. Generate some primes
    print("\n--- Prime Generation ---")
    for bits in [64, 128, 256]:
        p = gen_prime(bits)
        print(f"{bits}-bit prime: {p}")

    # 3. Safe prime
    print("\n--- Safe Prime Generation ---")
    p, q = gen_safe_prime(64)
    print(f"Safe prime p = {p}")
    print(f"Sophie Germain prime q = {q}")
    print(f"p = 2q + 1? {p == 2 * q + 1}")
    g = find_generator(p, q)
    print(f"Generator g = {g}")
    print(f"g^q mod p = {mod_exp(g, q, p)} (should be 1)")

    # 4. Benchmark
    print("\n--- Benchmark ---")
    results = benchmark_prime_generation([64, 128, 256])
    for bits, r in results.items():
        print(f"{bits}-bit: avg {r['avg_candidates']:.1f} candidates, "
              f"{r['avg_time_sec']:.4f}s, "
              f"theoretical ~{r['theoretical_candidates']:.0f}")
