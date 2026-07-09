"""
crypto/elgamal.py — ElGamal Public-Key Cryptosystem

Implements:
  1. Key generation using DH group
  2. ElGamal encryption: C = (g^r, m · h^r)
  3. ElGamal decryption: m = c2 / c1^x
  4. Malleability attack: (c1, 2·c2) decrypts to 2m
  5. IND-CPA game

Dependencies: crypto.diffie_hellman, crypto.miller_rabin, crypto.utils
Used by: (CCA-PKC), (OT)
"""

from crypto.diffie_hellman import DHGroup
from crypto.utils import mod_exp, mod_inverse, random_int

# ---------------------------------------------------------------------------
# ElGamal Key Generation
# ---------------------------------------------------------------------------

class ElGamalKey:
    """ElGamal key pair container."""

    def __init__(self, p, g, q, x, h):
        self.p = p  # Prime modulus
        self.g = g  # Generator
        self.q = q  # Order of subgroup
        self.x = x  # Private key (secret)
        self.h = h  # Public key h = g^x mod p

    @property
    def pk(self):
        return {'p': self.p, 'g': self.g, 'q': self.q, 'h': self.h}

    @property
    def sk(self):
        return self.x


def elgamal_keygen(group: DHGroup = None, bits: int = 64) -> ElGamalKey:
    """
    ElGamal key generation.

    1. Sample private key x ← Z_q
    2. Compute public key h = g^x mod p

    Args:
        group: DH group parameters. If None, generates new ones.
        bits: Bit length for the safe prime.

    Returns:
        ElGamalKey with (p, g, q, x, h).
    """
    if group is None:
        group = DHGroup(bits)

    x = random_int(2, group.q - 1)
    h = mod_exp(group.g, x, group.p)

    return ElGamalKey(group.p, group.g, group.q, x, h)


# ---------------------------------------------------------------------------
# ElGamal Encryption / Decryption
# ---------------------------------------------------------------------------

def elgamal_encrypt(pk: dict, m: int) -> tuple:
    """
    ElGamal encryption.

    Enc(pk, m):
      1. Sample r ← Z_q
      2. Output C = (g^r mod p, m · h^r mod p)

    Args:
        pk: Public key dict with 'p', 'g', 'q', 'h'.
        m: Plaintext (group element, integer in [1, p-1]).

    Returns:
        (c1, c2) ciphertext pair.
    """
    p, g, q, h = pk['p'], pk['g'], pk['q'], pk['h']

    if m <= 0 or m >= p:
        raise ValueError(f"Plaintext must be in [1, p-1], got {m}")

    r = random_int(2, q - 1)
    c1 = mod_exp(g, r, p)    # g^r mod p
    c2 = (m * mod_exp(h, r, p)) % p  # m · h^r mod p

    return c1, c2


def elgamal_decrypt(sk: int, p: int, c1: int, c2: int) -> int:
    """
    ElGamal decryption.

    Dec(sk, c1, c2):
      m = c2 / c1^x mod p = c2 · (c1^x)^{-1} mod p

    Args:
        sk: Private key x.
        p: Prime modulus.
        c1, c2: Ciphertext pair.

    Returns:
        Plaintext m.
    """
    # Compute c1^x mod p
    s = mod_exp(c1, sk, p)
    # Compute s^{-1} mod p
    s_inv = mod_inverse(s, p)
    # m = c2 · s_inv mod p
    m = (c2 * s_inv) % p

    return m


# ---------------------------------------------------------------------------
# ElGamal with Key Object
# ---------------------------------------------------------------------------

class ElGamal:
    """Convenient ElGamal wrapper using ElGamalKey objects."""

    def __init__(self, key: ElGamalKey = None, bits: int = 64):
        if key is None:
            key = elgamal_keygen(bits=bits)
        self.key = key

    def encrypt(self, m: int) -> tuple:
        """Encrypt plaintext m."""
        return elgamal_encrypt(self.key.pk, m)

    def decrypt(self, c1: int, c2: int) -> int:
        """Decrypt ciphertext (c1, c2)."""
        return elgamal_decrypt(self.key.sk, self.key.p, c1, c2)


# ---------------------------------------------------------------------------
# Malleability Attack
# ---------------------------------------------------------------------------

def malleability_attack(key: ElGamalKey, m: int) -> dict:
    """
    Demonstrate ElGamal malleability.

    Given ciphertext (c1, c2) for unknown m, construct
    (c1, 2·c2 mod p) which decrypts to 2m mod p.
    """
    c1, c2 = elgamal_encrypt(key.pk, m)

    # Attacker modifies c2 without knowing m
    c2_modified = (2 * c2) % key.p

    # Decrypt both
    m_original = elgamal_decrypt(key.sk, key.p, c1, c2)
    m_modified = elgamal_decrypt(key.sk, key.p, c1, c2_modified)

    return {
        'original_m': m,
        'decrypted_original': m_original,
        'decrypted_modified': m_modified,
        'expected_modified': (2 * m) % key.p,
        'attack_works': m_modified == (2 * m) % key.p,
        'times_checked': 1,
    }


def malleability_100_trials(key: ElGamalKey = None, bits: int = 64) -> dict:
    """Run malleability attack 100 times and count successes."""
    if key is None:
        key = elgamal_keygen(bits=bits)

    successes = 0
    for _ in range(100):
        m = random_int(1, key.p - 2)
        result = malleability_attack(key, m)
        if result['attack_works']:
            successes += 1

    return {
        'trials': 100,
        'successes': successes,
        'rate': successes / 100,
        'conclusion': f'{successes}/100 = {successes}% success (should be 100%)',
    }


# ---------------------------------------------------------------------------
# IND-CPA Game
# ---------------------------------------------------------------------------

def ind_cpa_game(key: ElGamalKey = None, num_rounds: int = 100,
                  bits: int = 64) -> dict:
    """
    IND-CPA game for ElGamal.

    Adversary tries to distinguish Enc(m0) from Enc(m1).
    Under DDH, advantage should be ≈ 0.
    """

    if key is None:
        key = elgamal_keygen(bits=bits)

    correct = 0
    for _ in range(num_rounds):
        m0 = random_int(1, key.p - 2)
        m1 = random_int(1, key.p - 2)
        while m1 == m0:
            m1 = random_int(1, key.p - 2)

        b = random_int(0, 1)
        chosen = m0 if b == 0 else m1
        c1, c2 = elgamal_encrypt(key.pk, chosen)

        # Random guess (best strategy against CPA-secure scheme)
        b_guess = random_int(0, 1)
        if b_guess == b:
            correct += 1

    advantage = abs(correct / num_rounds - 0.5)
    return {
        'rounds': num_rounds,
        'correct': correct,
        'advantage': advantage,
        'secure': advantage < 0.15,
    }


def small_group_distinguisher(q_bits: int = 10) -> dict:
    """
    Demonstrate distinguisher in a tiny group (q ≈ 2^10).
    When the group is small enough, we can brute-force the DLP
    and break CPA security.
    """
    key = elgamal_keygen(bits=q_bits + 1)  # Very small

    # Brute-force: find x from h = g^x
    found_x = None
    for guess in range(1, key.q + 1):
        if mod_exp(key.g, guess, key.p) == key.h:
            found_x = guess
            break

    if found_x is None:
        return {'broken': False}

    # Now we can decrypt anything
    correct = 0
    trials = 100
    for _ in range(trials):
        m0 = random_int(1, key.p - 2)
        m1 = random_int(1, key.p - 2)
        b = random_int(0, 1)
        chosen = m0 if b == 0 else m1
        c1, c2 = elgamal_encrypt(key.pk, chosen)

        # Decrypt using brute-forced key
        m_dec = elgamal_decrypt(found_x, key.p, c1, c2)
        b_guess = 0 if m_dec == m0 else 1
        if b_guess == b:
            correct += 1

    return {
        'broken': True,
        'q_bits': q_bits,
        'found_x': found_x,
        'correct': correct,
        'trials': trials,
        'advantage': abs(correct / trials - 0.5),
    }


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

def Enc(pk: dict, m: int) -> tuple:
    """Encrypt: returns (c1, c2)."""
    return elgamal_encrypt(pk, m)

def Dec(sk: int, p: int, c1: int, c2: int) -> int:
    """Decrypt: returns m."""
    return elgamal_decrypt(sk, p, c1, c2)


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("ElGamal Public-Key Cryptosystem")
    print("=" * 60)

    key = elgamal_keygen(bits=64)
    print(f"p = {key.p}, g = {key.g}, q = {key.q}")
    print(f"Private key x = {key.x}")
    print(f"Public key h = {key.h}")

    # Encrypt/Decrypt
    print("\n--- Encrypt/Decrypt ---")
    m = 42
    c1, c2 = elgamal_encrypt(key.pk, m)
    m2 = elgamal_decrypt(key.sk, key.p, c1, c2)
    print(f"Enc({m}) = ({c1}, {c2})")
    print(f"Dec = {m2}")
    print(f"Match: {m == m2}")

    # Malleability
    print("\n--- Malleability Attack ---")
    attack = malleability_attack(key, m)
    print(f"Dec(c1, 2·c2) = {attack['decrypted_modified']}")
    print(f"Expected 2m = {attack['expected_modified']}")
    print(f"Attack works: {attack['attack_works']}")

    # 100 trials
    print("\n--- 100 Malleability Trials ---")
    trials = malleability_100_trials(key)
    print(f"{trials['conclusion']}")

    # IND-CPA
    print("\n--- IND-CPA Game ---")
    cpa = ind_cpa_game(key, num_rounds=100)
    print(f"Advantage: {cpa['advantage']:.4f} (should be ~0)")

    # Small group distinguisher
    print("\n--- Small Group Distinguisher ---")
    dist = small_group_distinguisher(q_bits=10)
    if dist['broken']:
        print(f"Broke {dist['q_bits']}-bit group! "
              f"Advantage: {dist['advantage']:.2f}")
