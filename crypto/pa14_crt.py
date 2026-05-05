"""
crypto/pa14_crt.py — PA#14: Chinese Remainder Theorem + Håstad Broadcast Attack

Implements:
  1. Chinese Remainder Theorem (multi-modulus)
  2. RSA decryption via CRT (Garner's algorithm, ~4× speedup)
  3. Performance benchmark (CRT vs standard)
  4. Håstad broadcast attack (e=3, same plaintext, different moduli)
  5. Integer n-th root via Newton's method

Dependencies: crypto.pa12_rsa, crypto.pa13_miller_rabin, crypto.utils
"""

import time
from crypto.utils import mod_exp, mod_inverse, random_int, to_hex
from crypto.pa12_rsa import rsa_keygen, rsa_encrypt, rsa_decrypt, RSAKeyPair


# ---------------------------------------------------------------------------
# Chinese Remainder Theorem
# ---------------------------------------------------------------------------

def crt(residues: list, moduli: list) -> int:
    """
    Chinese Remainder Theorem: find x such that
    x ≡ r_i (mod m_i) for all i.

    Args:
        residues: List of residues [r_0, r_1, ...].
        moduli: List of moduli [m_0, m_1, ...] (must be pairwise coprime).

    Returns:
        x: The unique solution modulo M = ∏ m_i.
    """
    if len(residues) != len(moduli):
        raise ValueError("Residues and moduli must have same length")

    M = 1
    for m in moduli:
        M *= m

    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m  # Product of all moduli except m
        yi = mod_inverse(Mi, m)  # Mi^{-1} mod m
        x += r * Mi * yi

    return x % M


# ---------------------------------------------------------------------------
# RSA Decryption via CRT
# ---------------------------------------------------------------------------

def rsa_decrypt_crt(kp: RSAKeyPair, c: int) -> int:
    """
    RSA decryption using CRT (Garner's algorithm).
    Approximately 4× faster than standard RSA decryption.

    Instead of computing m = c^d mod n directly:
    1. m_p = c^{d mod (p-1)} mod p
    2. m_q = c^{d mod (q-1)} mod q
    3. Combine using CRT: m = m_q + q * (q_inv * (m_p - m_q) mod p)
    """
    if kp.p is None or kp.q is None:
        raise ValueError("CRT decryption requires p and q")

    # Step 1: Compute partial decryptions
    dp = kp.d % (kp.p - 1)
    dq = kp.d % (kp.q - 1)
    m_p = mod_exp(c, dp, kp.p)
    m_q = mod_exp(c, dq, kp.q)

    # Step 2: Garner's combination
    q_inv = mod_inverse(kp.q, kp.p)
    h = (q_inv * (m_p - m_q)) % kp.p
    m = m_q + kp.q * h

    return m


def benchmark_crt(bits: int = 512, trials: int = 10) -> dict:
    """
    Benchmark CRT vs standard RSA decryption.
    """
    kp = rsa_keygen(bits)
    m = random_int(2, kp.n - 1)
    c = rsa_encrypt(kp.n, kp.e, m)

    # Standard decryption
    start = time.time()
    for _ in range(trials):
        m_std = rsa_decrypt(kp.d, kp.n, c)
    std_time = (time.time() - start) / trials

    # CRT decryption
    start = time.time()
    for _ in range(trials):
        m_crt = rsa_decrypt_crt(kp, c)
    crt_time = (time.time() - start) / trials

    return {
        'bits': bits,
        'standard_time_ms': std_time * 1000,
        'crt_time_ms': crt_time * 1000,
        'speedup': std_time / crt_time if crt_time > 0 else float('inf'),
        'correct': m_std == m_crt == m,
    }


# ---------------------------------------------------------------------------
# Integer n-th Root (Newton's Method)
# ---------------------------------------------------------------------------

def integer_nth_root(x: int, n: int) -> int:
    """
    Compute the integer n-th root of x: floor(x^{1/n}).
    Uses Newton's method for arbitrary precision.

    Returns r such that r^n ≤ x < (r+1)^n.
    """
    if x < 0:
        raise ValueError("Cannot compute root of negative number")
    if x == 0:
        return 0
    if n == 1:
        return x

    # Initial guess using bit length
    bit_len = x.bit_length()
    guess = 1 << ((bit_len + n - 1) // n)

    # Newton iteration: r_{i+1} = ((n-1)*r_i + x/r_i^{n-1}) / n
    while True:
        guess_pow = guess ** (n - 1)
        new_guess = ((n - 1) * guess + x // guess_pow) // n
        if new_guess >= guess:
            break
        guess = new_guess

    # Final check
    while guess ** n > x:
        guess -= 1
    while (guess + 1) ** n <= x:
        guess += 1

    return guess


# ---------------------------------------------------------------------------
# Håstad Broadcast Attack
# ---------------------------------------------------------------------------

def hastad_attack(ciphertexts: list, moduli: list, e: int = 3) -> int:
    """
    Håstad's broadcast attack on textbook RSA with small e.

    Given e ciphertexts c_i = m^e mod n_i (same m, different n_i),
    use CRT to recover m^e, then compute the integer e-th root.

    This works because m^e < n_1 * n_2 * ... * n_e when m < each n_i.
    """
    if len(ciphertexts) < e:
        raise ValueError(f"Need at least e={e} ciphertexts")

    # Use CRT to find m^e mod (n_1 * n_2 * ... * n_e)
    m_e = crt(ciphertexts[:e], moduli[:e])

    # Compute the integer e-th root
    m = integer_nth_root(m_e, e)

    # Verify
    if m ** e == m_e:
        return m
    else:
        # Numerical issue — try nearby values
        for delta in range(-2, 3):
            candidate = m + delta
            if candidate >= 0 and candidate ** e == m_e:
                return candidate
        return m  # Best guess


def hastad_attack_demo(bits: int = 256, e: int = 3) -> dict:
    """
    Demonstrate Håstad's broadcast attack.

    Same message m encrypted under 3 different RSA keys with e=3.
    """
    # Generate e different RSA keys
    keys = [rsa_keygen(bits, e=e) for _ in range(e)]

    # Choose a random message (must be < all n_i)
    min_n = min(kp.n for kp in keys)
    m = random_int(2, min(min_n - 1, 2 ** (bits // 2)))

    # Encrypt under all keys
    ciphertexts = [rsa_encrypt(kp.n, kp.e, m) for kp in keys]
    moduli = [kp.n for kp in keys]

    # Run the attack
    start = time.time()
    m_recovered = hastad_attack(ciphertexts, moduli, e)
    elapsed = time.time() - start

    return {
        'original_m': m,
        'recovered_m': m_recovered,
        'success': m_recovered == m,
        'e': e,
        'num_keys': len(keys),
        'bits': bits,
        'time_sec': elapsed,
    }


def padding_defeats_hastad(bits: int = 256, e: int = 3) -> dict:
    """
    Show that PKCS#1 v1.5 padding defeats Håstad's attack
    because each ciphertext encrypts a different padded message.
    """
    from crypto.pa12_rsa import pkcs15_encrypt, pkcs15_decrypt

    keys = [rsa_keygen(bits, e=e) for _ in range(e)]
    message = b"Hi"

    # PKCS padded → different padded plaintexts (due to random PS)
    ciphertexts = [pkcs15_encrypt(kp.n, kp.e, message) for kp in keys]
    moduli = [kp.n for kp in keys]

    # Attempt Håstad attack
    m_e = crt(ciphertexts[:e], moduli[:e])
    m_guess = integer_nth_root(m_e, e)

    # Verify that the attack fails
    success = (m_guess ** e == m_e)

    return {
        'message': message,
        'hastad_succeeds': success,
        'reason': 'PKCS#1 v1.5 randomized padding makes each padded plaintext '
                  'different, so CRT recovers nothing useful.',
    }


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("PA#14: CRT + Håstad Broadcast Attack")
    print("=" * 60)

    # Basic CRT
    print("\n--- CRT Example ---")
    x = crt([2, 3, 2], [3, 5, 7])
    print(f"x ≡ 2 mod 3, x ≡ 3 mod 5, x ≡ 2 mod 7 → x = {x}")
    print(f"Check: {x%3}≡2, {x%5}≡3, {x%7}≡2")

    # CRT RSA decryption
    print("\n--- CRT RSA Benchmark ---")
    bench = benchmark_crt(bits=512, trials=5)
    print(f"Standard: {bench['standard_time_ms']:.2f} ms")
    print(f"CRT:      {bench['crt_time_ms']:.2f} ms")
    print(f"Speedup:  {bench['speedup']:.1f}×")
    print(f"Correct:  {bench['correct']}")

    # Håstad attack
    print("\n--- Håstad Broadcast Attack (e=3) ---")
    attack = hastad_attack_demo(bits=256, e=3)
    print(f"Original message: {attack['original_m']}")
    print(f"Recovered: {attack['recovered_m']}")
    print(f"Success: {attack['success']}")

    # Padding defeats attack
    print("\n--- Padding Defeats Håstad ---")
    defense = padding_defeats_hastad(bits=256, e=3)
    print(f"Håstad on padded: {defense['hastad_succeeds']} (should be False)")
    print(f"Reason: {defense['reason']}")
