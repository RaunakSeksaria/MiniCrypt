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

        if h in seen:
            if seen[h] != x:
                # Genuine collision: two distinct inputs with the same hash
                return {
                    'found': True,
                    'input1': seen[h],
                    'input2': x,
                    'hash_value': h,
                    'evaluations': evaluations,
                    'expected': 2 ** (n_bits / 2),
                    'ratio': evaluations / (2 ** (n_bits / 2)),
                }
            # else: exact same bytes drawn again — skip without overwriting
        else:
            seen[h] = x  # Only store on first encounter

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

    Treats the hash as f: {0,1}^n → {0,1}^n (truncated), builds the sequence
    x0, f(x0), f(f(x0)), ... which must eventually cycle.  Once the cycle is
    found, the two distinct predecessors of the cycle-entry node are a valid
    collision pair: f(tail_pred) == f(cycle_pred) == cycle_entry.

    Phases:
      1. Detect cycle  — tortoise (+1), hare (+2) until they meet.
      2. Find μ        — reset tortoise to x0, advance both at speed 1;
                         meeting point is the cycle entry x_μ.
      3. Extract pair  — tail_pred  = x_{μ-1}  (last node on the tail)
                         cycle_pred = x_{μ+λ-1} (last node in the cycle)
                         Both map to x_μ; they are distinct because one is on
                         the tail and one is in the cycle.

    If μ == 0 the starting point is already inside the cycle and no tail exists,
    so no collision can be extracted from this trajectory.  The function retries
    with a fresh random x0 (up to 20 attempts) before giving up.

    Args:
        hash_fn: Callable bytes → int (n_bits output).
        n_bits:  Output bit length.

    Returns:
        dict with collision details, or {'found': False, ...}.
    """
    if max_iterations is None:
        max_iterations = (1 << n_bits) + 10

    mask = (1 << n_bits) - 1
    evals = 0

    def f(x: int) -> int:
        nonlocal evals
        evals += 1
        n_bytes = max(1, (x.bit_length() + 7) // 8)
        return hash_fn(x.to_bytes(n_bytes, 'big')) & mask

    def to_bytes(v: int) -> bytes:
        return v.to_bytes(max(1, (v.bit_length() + 7) // 8), 'big')

    for _attempt in range(20):
        evals = 0
        x0 = bytes_to_int(random_bytes(2)) & mask

        # ------------------------------------------------------------------
        # Phase 1: Detect the cycle.
        # tortoise advances one step per iteration; hare advances two.
        # They meet somewhere inside the cycle after O(λ) iterations.
        # ------------------------------------------------------------------
        tortoise = f(x0)
        hare = f(f(x0))

        while tortoise != hare:
            tortoise = f(tortoise)
            hare = f(f(hare))
            if evals > max_iterations:
                return {'found': False, 'evaluations': evals}

        # ------------------------------------------------------------------
        # Phase 2: Find μ (the cycle entry index).
        # Reset tortoise to x0; advance both at speed 1.
        # They meet exactly at x_μ after μ more steps.
        # ------------------------------------------------------------------
        tortoise = x0
        mu = 0
        while tortoise != hare:
            tortoise = f(tortoise)
            hare = f(hare)
            mu += 1
            if evals > max_iterations:
                return {'found': False, 'evaluations': evals}

        if mu == 0:
            # x0 is already inside the cycle; there is no tail, so we cannot
            # extract a collision from this trajectory.  Retry with new x0.
            continue

        cycle_entry = tortoise  # == x_μ == f^μ(x0)

        # ------------------------------------------------------------------
        # Phase 3a: Find tail_pred = x_{μ-1}.
        # Walk μ-1 steps from x0 along the sequence.
        # f(tail_pred) == cycle_entry by construction.
        # ------------------------------------------------------------------
        tail_pred = x0
        for _ in range(mu - 1):
            tail_pred = f(tail_pred)
            if evals > max_iterations:
                return {'found': False, 'evaluations': evals}

        # ------------------------------------------------------------------
        # Phase 3b: Find cycle_pred = x_{μ+λ-1}.
        # Start at cycle_entry and walk until the next step returns to
        # cycle_entry.  That predecessor is the last node in the cycle.
        # f(cycle_pred) == cycle_entry by construction.
        # ------------------------------------------------------------------
        cycle_pred = cycle_entry
        while True:
            nxt = f(cycle_pred)
            if nxt == cycle_entry:
                break
            cycle_pred = nxt
            if evals > max_iterations:
                return {'found': False, 'evaluations': evals}

        # tail_pred is on the tail, cycle_pred is in the cycle → always distinct
        # (degenerate equal case is theoretically impossible when μ > 0, but guard)
        if tail_pred == cycle_pred:
            continue

        return {
            'found': True,
            'input1': to_bytes(tail_pred),
            'input2': to_bytes(cycle_pred),
            'hash_value': cycle_entry,
            'evaluations': evals,
            'expected': 2 ** (n_bits / 2),
            'cycle_detected': True,
        }

    return {'found': False, 'evaluations': evals}


# ---------------------------------------------------------------------------
# Toy Hash Functions
# ---------------------------------------------------------------------------

def make_toy_hash(n_bits: int):
    """
    Create a simple toy hash function with n_bits output.
    Uses SHA-256 truncated to n bits to ensure pseudorandom behavior.
    """
    mask = (1 << n_bits) - 1
    import hashlib

    def toy_hash(data: bytes) -> int:
        h = hashlib.sha256(data).digest()
        return bytes_to_int(h) & mask

    return toy_hash


# ---------------------------------------------------------------------------
# Attack Experiments
# ---------------------------------------------------------------------------

def attack_toy_hash(n_bits_list=None, num_trials: int = 20):
    """
    Run birthday attacks on toy hashes of various output sizes.
    """
    if n_bits_list is None:
        n_bits_list = [8, 12, 16]

    results = {}
    for n in n_bits_list:
        hash_fn = make_toy_hash(n)
        evals_list_naive = []
        evals_list_floyd = []

        for _ in range(num_trials):
            res_naive = birthday_attack_naive(hash_fn, n)
            if res_naive['found']:
                evals_list_naive.append(res_naive['evaluations'])

            res_floyd = birthday_attack_floyd(hash_fn, n)
            if res_floyd['found']:
                evals_list_floyd.append(res_floyd['evaluations'])

        avg_naive = sum(evals_list_naive) / len(evals_list_naive) if evals_list_naive else 0
        avg_floyd = sum(evals_list_floyd) / len(evals_list_floyd) if evals_list_floyd else 0
        expected = 2 ** (n / 2)
        results[n] = {
            'avg_evaluations_naive': avg_naive,
            'avg_evaluations_floyd': avg_floyd,
            'expected_birthday': expected,
            'ratio_naive': avg_naive / expected if expected else 0,
            'ratio_floyd': avg_floyd / expected if expected else 0,
            'trials': num_trials,
        }

    try:
        import matplotlib.pyplot as plt
        n_vals = sorted(results.keys())
        expected_vals = [results[n]['expected_birthday'] for n in n_vals]
        naive_vals = [results[n]['avg_evaluations_naive'] for n in n_vals]
        floyd_vals = [results[n]['avg_evaluations_floyd'] for n in n_vals]

        plt.figure(figsize=(8, 5))
        plt.plot(n_vals, expected_vals, 'k--', label='Theoretical $2^{n/2}$')
        plt.plot(n_vals, naive_vals, 'bo-', label='Empirical (Naive)')
        plt.plot(n_vals, floyd_vals, 'rs-', label='Empirical (Floyd)')
        plt.xlabel('Hash Output Bits (n)')
        plt.ylabel('Evaluations until Collision')
        plt.title('Birthday Attack: Evaluations vs Output Size')
        plt.yscale('log')
        plt.legend()
        plt.grid(True, which="both", ls="-", alpha=0.2)
        plt.savefig('toy_hash_evals.png')
        plt.close()
        print("Plot saved as 'toy_hash_evals.png'")
    except ImportError:
        pass

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
    last_collision = None
    for _ in range(num_trials):
        result = birthday_attack_naive(truncated_hash, output_bits)
        if result['found']:
            evals_list.append(result['evaluations'])
            last_collision = result

    avg = sum(evals_list) / len(evals_list) if evals_list else 0
    expected = 2 ** (output_bits / 2)

    return {
        'output_bits': output_bits,
        'avg_evaluations': avg,
        'expected': expected,
        'ratio': avg / expected if expected > 0 else 0,
        'trials': num_trials,
        'successes': len(evals_list),
        'input1': last_collision['input1'].hex() if last_collision else None,
        'input2': last_collision['input2'].hex() if last_collision else None,
        'hash_value': last_collision['hash_value'] if last_collision else None,
    }


def empirical_birthday_curve(n_bits_list=None, num_trials: int = 100):
    """
    Run many trials and plot the distribution of evaluations until collision.
    """
    if n_bits_list is None:
        n_bits_list = [8, 10, 12, 14, 16]

    all_data = {}

    try:
        import matplotlib.pyplot as plt
        import numpy as np
        plt.figure(figsize=(10, 6))
    except ImportError:
        plt = None
        np = None

    for n_bits in n_bits_list:
        hash_fn = make_toy_hash(n_bits)
        evaluations_list = []

        for _ in range(num_trials):
            result = birthday_attack_naive(hash_fn, n_bits)
            if result['found']:
                evaluations_list.append(result['evaluations'])

        evaluations_list.sort()
        expected = 2 ** (n_bits / 2)

        if plt is not None:
            # Plot Empirical CDF
            y_vals = np.arange(1, len(evaluations_list) + 1) / len(evaluations_list)
            p = plt.plot(evaluations_list, y_vals, label=f'Empirical n={n_bits}',
                         marker='.', linestyle='none', alpha=0.6)

            # Overlay Theoretical Curve: 1 - exp(-k*(k-1)/(2 * 2^n))
            k_vals = np.linspace(1, max(evaluations_list) if evaluations_list else 100, 200)
            theo_y = 1.0 - np.exp(-k_vals * (k_vals - 1) / (2.0 * (2 ** n_bits)))
            plt.plot(k_vals, theo_y, color=p[0].get_color(), linestyle='-', alpha=0.8)

        all_data[n_bits] = {
            'num_trials': num_trials,
            'mean': sum(evaluations_list) / len(evaluations_list) if evaluations_list else 0,
            'expected_birthday': expected,
        }

    if plt is not None:
        plt.xlabel('Evaluations (k)')
        plt.ylabel('Probability of Collision')
        plt.title('Empirical vs Theoretical Birthday Curve')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig('empirical_birthday_curve.png')
        plt.close()
        print("Plot saved as 'empirical_birthday_curve.png'")

    return all_data


def practical_context():
    """
    Compute 2^{n/2} for practical hash functions to contextualise security.

    Note: these figures assume a *generic* birthday attack with no structural
    weaknesses exploited.  Real-world attacks on MD5 and SHA-1 used differential
    cryptanalysis to find collisions far below 2^{n/2}; the birthday bound is a
    ceiling, not a description of the actual attack cost.
    """
    _interpretations = {
        'MD5': (
            'Broken. Wang et al. (2004) found collisions in ~2^24 ops using '
            'differential cryptanalysis — orders of magnitude below the 2^64 '
            'birthday bound. MD5 should never be used for integrity or signing.'
        ),
        'SHA-1': (
            'Deprecated. The SHAttered attack (2017) produced a practical PDF '
            'collision at an estimated cost of ~2^63 ops, roughly half the '
            '2^80 birthday bound. All major browsers and CAs have dropped SHA-1.'
        ),
        'SHA-256': (
            'Currently secure. No structural attack is known; the full 2^128 '
            'birthday cost is computationally infeasible with any foreseeable '
            'technology. Recommended for new systems.'
        ),
    }

    results = {}
    for name, n in [('MD5', 128), ('SHA-1', 160), ('SHA-256', 256)]:
        cost = 2 ** (n / 2)
        seconds = cost / 1e9          # at 10^9 hashes/sec
        years = seconds / (365.25 * 24 * 3600)

        results[name] = {
            'output_bits': n,
            'collision_cost': f'2^{n // 2}',
            'cost_decimal': f'{cost:.2e}',
            'seconds_at_1ghz': f'{seconds:.2e}',
            'years_at_1ghz': f'{years:.2e}',
            'interpretation': _interpretations[name],
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
    results = attack_toy_hash([8, 12, 16], num_trials=20)
    print(f"{'n':>4} | {'Avg Evals (Naive)':>18} | {'Avg Evals (Floyd)':>18} | {'Expected':>10}")
    print("-" * 58)
    for n, r in sorted(results.items()):
        print(f"{n:>4} | {r['avg_evaluations_naive']:>18.1f} | "
              f"{r['avg_evaluations_floyd']:>18.1f} | {r['expected_birthday']:>10.1f}")

    print("\n--- Attack Truncated DLP Hash ---")
    dlp_res = attack_dlp_hash_truncated(16, 5)
    print(f"n = 16 bits | Avg Evals: {dlp_res['avg_evaluations']:.1f} | "
          f"Expected: {dlp_res['expected']:.1f} | Ratio: {dlp_res['ratio']:.2f}")
    if dlp_res.get('input1'):
        print(f"Example Collision: H({dlp_res['input1']}) == H({dlp_res['input2']}) "
              f"== {dlp_res['hash_value']}")

    # Practical context
    print("\n--- Practical Hash Context ---")
    ctx = practical_context()
    for name, info in ctx.items():
        print(f"\n{name} (n={info['output_bits']} bits)")
        print(f"  Generic birthday cost : {info['collision_cost']} ≈ {info['cost_decimal']} ops")
        print(f"  At 1 GHash/s          : ≈ {info['years_at_1ghz']} years")
        print(f"  Security assessment   : {info['interpretation']}")

    # Empirical curve
    print("\n--- Empirical Birthday Curve ---")
    curve_data = empirical_birthday_curve([8, 10, 12, 14, 16], 100)
    for n, info in curve_data.items():
        print(f"n={n:>2}: Mean = {info['mean']:.1f} | Expected = {info['expected_birthday']:.1f}")