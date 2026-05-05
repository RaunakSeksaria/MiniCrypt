"""
crypto/pa09_birthday.py — PA#9: Birthday Attack (Collision Finding)

Implements:
  1. Naive birthday algorithm (sort-based): O(2^{n/2}) time, O(2^{n/2}) space
  2. Floyd's cycle detection: O(2^{n/2}) time, O(1) space
  3. Attack on toy hash functions (n = 8, 12, 16 bits)
  4. Attack on truncated DLP hash
  5. Empirical birthday curve

Dependencies: crypto.pa08_dlp_crhf, crypto.utils
"""

import time
import math
from crypto.utils import random_bytes, bytes_to_int, to_hex


# ---------------------------------------------------------------------------
# Naive Birthday Algorithm (Dictionary-based)
# ---------------------------------------------------------------------------

def birthday_attack_naive(hash_fn, n_bits: int, max_trials: int = None):
    """
    Naive birthday collision finder.

    Hashes random inputs, stores in dictionary, returns first collision.

    Args:
        hash_fn: Callable that takes bytes → int (n_bits output).
        n_bits: Output bit length of hash.
        max_trials: Maximum evaluations before giving up.

    Returns:
        dict with collision details, or None if not found.
    """
    if max_trials is None:
        max_trials = int(3 * (2 ** (n_bits / 2)))  # ~3× birthday bound

    seen = {}  # hash_value → input
    evaluations = 0

    for _ in range(max_trials):
        x = random_bytes(8)  # Random 8-byte input
        h = hash_fn(x)
        evaluations += 1

        if h in seen and seen[h] != x:
            return {
                'found': True,
                'input1': seen[h],
                'input2': x,
                'hash_value': h,
                'evaluations': evaluations,
                'expected': 2 ** (n_bits / 2),
                'ratio': evaluations / (2 ** (n_bits / 2)),
            }
        seen[h] = x

    return {
        'found': False,
        'evaluations': evaluations,
        'expected': 2 ** (n_bits / 2),
    }


# ---------------------------------------------------------------------------
# Floyd's Cycle Detection (Space-efficient)
# ---------------------------------------------------------------------------

def birthday_attack_floyd(hash_fn, n_bits: int, max_iterations: int = None):
    """
    Space-efficient collision finder using Floyd's tortoise-and-hare.

    Treats hash as f: {0,1}^n → {0,1}^n (truncated).
    Uses tortoise and hare to find a cycle, then extracts collision.

    Args:
        hash_fn: Callable that takes int → int (maps n-bit → n-bit).
        n_bits: Output bit length.

    Returns:
        dict with collision details.
    """
    if max_iterations is None:
        max_iterations = int(10 * (2 ** (n_bits / 2)))

    mask = (1 << n_bits) - 1

    def f(x):
        """Treat hash as a function on n-bit integers."""
        x_bytes = x.to_bytes(max(1, (x.bit_length() + 7) // 8), 'big')
        return hash_fn(x_bytes) & mask

    # Phase 1: Find a point in the cycle
    # Start from a random point
    x0 = bytes_to_int(random_bytes(2)) & mask
    tortoise = f(x0)
    hare = f(f(x0))

    iterations = 0
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(f(hare))
        iterations += 1
        if iterations > max_iterations:
            return {'found': False, 'evaluations': iterations * 3}

    # Phase 2: Find the actual collision
    # Both pointers start from the beginning of the cycle entry
    tortoise = x0
    while tortoise != hare:
        prev_t, prev_h = tortoise, hare
        tortoise = f(tortoise)
        hare = f(hare)
        iterations += 1

    # Phase 3: Find two distinct inputs that produce the same output
    # Walk until we find f(a) == f(b) with a ≠ b
    if tortoise == x0:
        # Special case: cycle starts at x0
        a = tortoise
        b = f(a)
        while f(a) != f(b) or a == b:
            a = f(a)
            b = f(f(b))
            iterations += 1
            if iterations > max_iterations:
                return {'found': False, 'evaluations': iterations}

    return {
        'found': True,
        'evaluations': iterations * 3,  # Approximate
        'expected': 2 ** (n_bits / 2),
        'cycle_detected': True,
    }


# ---------------------------------------------------------------------------
# Toy Hash Functions
# ---------------------------------------------------------------------------

def make_toy_hash(n_bits: int):
    """
    Create a simple toy hash function with n_bits output.
    Uses a polynomial hash truncated to n bits.
    """
    mask = (1 << n_bits) - 1

    def toy_hash(data: bytes) -> int:
        # Simple polynomial hash
        h = 0x12345
        for b in data:
            h = ((h * 31) + b) & 0xFFFFFFFF
        return h & mask

    return toy_hash


# ---------------------------------------------------------------------------
# Attack Experiments
# ---------------------------------------------------------------------------

def attack_toy_hash(n_bits_list=None, num_trials: int = 20):
    """
    Run birthday attacks on toy hashes of various output sizes.
    """
    if n_bits_list is None:
        n_bits_list = [8, 10, 12, 14, 16]

    results = {}
    for n in n_bits_list:
        hash_fn = make_toy_hash(n)
        evals_list = []

        for _ in range(num_trials):
            result = birthday_attack_naive(hash_fn, n)
            if result['found']:
                evals_list.append(result['evaluations'])

        if evals_list:
            avg_evals = sum(evals_list) / len(evals_list)
            expected = 2 ** (n / 2)
            results[n] = {
                'avg_evaluations': avg_evals,
                'expected_birthday': expected,
                'ratio': avg_evals / expected,
                'successes': len(evals_list),
                'trials': num_trials,
            }

    return results


def attack_dlp_hash_truncated(output_bits: int = 16,
                               num_trials: int = 5) -> dict:
    """
    Attack the DLP hash from PA#8 with truncated output.
    """
    from crypto.pa08_dlp_crhf import DLP_CRHF

    crhf = DLP_CRHF(bits=32)  # Small group for speed
    mask = (1 << output_bits) - 1

    def truncated_hash(data: bytes) -> int:
        return bytes_to_int(crhf.hash(data)) & mask

    evals_list = []
    for _ in range(num_trials):
        result = birthday_attack_naive(truncated_hash, output_bits)
        if result['found']:
            evals_list.append(result['evaluations'])

    avg = sum(evals_list) / len(evals_list) if evals_list else 0
    expected = 2 ** (output_bits / 2)

    return {
        'output_bits': output_bits,
        'avg_evaluations': avg,
        'expected': expected,
        'ratio': avg / expected if expected > 0 else 0,
        'trials': num_trials,
        'successes': len(evals_list),
    }


def empirical_birthday_curve(n_bits: int = 12, num_trials: int = 100):
    """
    Run many trials and plot the distribution of evaluations until collision.
    Returns data points for plotting.
    """
    hash_fn = make_toy_hash(n_bits)
    evaluations_list = []

    for _ in range(num_trials):
        result = birthday_attack_naive(hash_fn, n_bits)
        if result['found']:
            evaluations_list.append(result['evaluations'])

    evaluations_list.sort()
    expected = 2 ** (n_bits / 2)

    return {
        'n_bits': n_bits,
        'num_trials': num_trials,
        'evaluations': evaluations_list,
        'median': evaluations_list[len(evaluations_list) // 2] if evaluations_list else 0,
        'mean': sum(evaluations_list) / len(evaluations_list) if evaluations_list else 0,
        'expected_birthday': expected,
    }


def practical_context():
    """
    Compute 2^{n/2} for practical hash functions to contextualize security.
    """
    results = {}
    for name, n in [('MD5', 128), ('SHA-1', 160), ('SHA-256', 256)]:
        cost = 2 ** (n / 2)
        # Assume 10^9 hashes/sec
        seconds = cost / 1e9
        years = seconds / (365.25 * 24 * 3600)

        results[name] = {
            'output_bits': n,
            'collision_cost': f'2^{n//2}',
            'cost_decimal': f'{cost:.2e}',
            'seconds_at_1ghz': f'{seconds:.2e}',
            'years_at_1ghz': f'{years:.2e}',
        }

    return results


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("PA#9: Birthday Attack (Collision Finding)")
    print("=" * 60)

    # Toy hash attacks
    print("\n--- Birthday Attack on Toy Hashes ---")
    results = attack_toy_hash([8, 10, 12, 14, 16], num_trials=10)
    print(f"{'n':>4} | {'Avg Evals':>10} | {'Expected':>10} | {'Ratio':>6}")
    print("-" * 40)
    for n, r in sorted(results.items()):
        print(f"{n:>4} | {r['avg_evaluations']:>10.1f} | "
              f"{r['expected_birthday']:>10.1f} | {r['ratio']:>6.2f}")

    # Practical context
    print("\n--- Practical Hash Context ---")
    ctx = practical_context()
    for name, info in ctx.items():
        print(f"{name}: collision cost = {info['collision_cost']}, "
              f"≈ {info['years_at_1ghz']} years at 1 GHash/s")

    # Empirical curve
    print("\n--- Empirical Birthday Curve (n=12, 50 trials) ---")
    curve = empirical_birthday_curve(12, 50)
    print(f"Expected: {curve['expected_birthday']:.0f}")
    print(f"Mean evaluations: {curve['mean']:.1f}")
    print(f"Median: {curve['median']}")
