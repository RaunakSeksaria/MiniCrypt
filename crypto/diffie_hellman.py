"""
crypto/diffie_hellman.py — Diffie-Hellman Key Exchange

Implements:
  1. DH group parameter generation (safe prime, generator)
  2. Full DH key exchange protocol (Alice & Bob steps)
  3. MITM attack demonstration (Eve intercepts)
  4. CDH hardness verification

Dependencies: crypto.miller_rabin (safe prime generation)
Used by: (ElGamal)
"""

from crypto.utils import mod_exp, random_int, random_bytes, to_hex, int_to_bytes
from crypto.miller_rabin import gen_safe_prime, find_generator


# ---------------------------------------------------------------------------
# DH Group Parameters
# ---------------------------------------------------------------------------

class DHGroup:
    """Diffie-Hellman group parameters: safe prime p, order q, generator g."""

    def __init__(self, bits: int = 64):
        self.p, self.q = gen_safe_prime(bits)
        self.g = find_generator(self.p, self.q)
        self.bits = bits

    def __repr__(self):
        return f"DHGroup(bits={self.bits}, p={self.p}, g={self.g}, q={self.q})"


# ---------------------------------------------------------------------------
# DH Key Exchange
# ---------------------------------------------------------------------------

class DiffieHellman:
    """Full Diffie-Hellman key exchange."""

    def __init__(self, group: DHGroup = None, bits: int = 64):
        if group is None:
            group = DHGroup(bits)
        self.group = group
        self.p = group.p
        self.q = group.q
        self.g = group.g

    def alice_step1(self) -> tuple:
        """Alice: pick random a, compute A = g^a mod p. Returns (a, A)."""
        a = random_int(2, self.q - 1)
        A = mod_exp(self.g, a, self.p)
        return a, A

    def bob_step1(self) -> tuple:
        """Bob: pick random b, compute B = g^b mod p. Returns (b, B)."""
        b = random_int(2, self.q - 1)
        B = mod_exp(self.g, b, self.p)
        return b, B

    def alice_step2(self, a: int, B: int) -> int:
        """Alice: compute shared key K = B^a mod p."""
        return mod_exp(B, a, self.p)

    def bob_step2(self, b: int, A: int) -> int:
        """Bob: compute shared key K = A^b mod p."""
        return mod_exp(A, b, self.p)

    def key_exchange(self) -> dict:
        """Full DH key exchange, returns all values for visualization."""
        a, A = self.alice_step1()
        b, B = self.bob_step1()
        K_alice = self.alice_step2(a, B)
        K_bob = self.bob_step2(b, A)

        return {
            'p': self.p, 'g': self.g, 'q': self.q,
            'a': a, 'A': A,  # Alice's private/public
            'b': b, 'B': B,  # Bob's private/public
            'K_alice': K_alice,
            'K_bob': K_bob,
            'keys_match': K_alice == K_bob,
        }


# ---------------------------------------------------------------------------
# MITM Attack
# ---------------------------------------------------------------------------

def mitm_attack(dh: DiffieHellman = None) -> dict:
    """
    Demonstrate MITM attack on vanilla DH.

    Eve intercepts A and B, substitutes her own values,
    establishing two independent shared keys.
    """
    if dh is None:
        dh = DiffieHellman(bits=64)

    # Alice
    a, A = dh.alice_step1()
    # Eve intercepts A, generates her own keys with Alice
    e1, E1 = dh.alice_step1()  # Eve's key for Alice
    e2, E2 = dh.alice_step1()  # Eve's key for Bob

    # Bob (receives E1 instead of A)
    b, B = dh.bob_step1()

    # Eve intercepts B, sends E2 to Alice

    # Shared keys
    K_alice = dh.alice_step2(a, E2)  # Alice thinks she shares with Bob
    K_eve_alice = dh.bob_step2(e2, A)  # Eve's key with Alice
    K_bob = dh.bob_step2(b, E1)  # Bob thinks he shares with Alice
    K_eve_bob = dh.alice_step2(e1, B)  # Eve's key with Bob

    return {
        'alice_key': K_alice,
        'eve_alice_key': K_eve_alice,
        'eve_has_alice_key': K_alice == K_eve_alice,
        'bob_key': K_bob,
        'eve_bob_key': K_eve_bob,
        'eve_has_bob_key': K_bob == K_eve_bob,
        'alice_bob_same': K_alice == K_bob,  # Should be False
        'attack_success': K_alice == K_eve_alice and K_bob == K_eve_bob,
        'explanation': 'Eve establishes separate keys with Alice and Bob. '
                       'She can decrypt, read, modify, and re-encrypt all messages.',
    }


# ---------------------------------------------------------------------------
# CDH Hardness
# ---------------------------------------------------------------------------

def cdh_hardness_demo(dh: DiffieHellman = None, tiny_bits: int = 20) -> dict:
    """
    Demonstrate CDH hardness: given (g, g^a, g^b), compute g^{ab}.
    For tiny parameters, brute-force is feasible; for large ones, it isn't.
    """
    if dh is None:
        dh = DiffieHellman(bits=tiny_bits)

    a, A = dh.alice_step1()
    b, B = dh.bob_step1()
    K_real = dh.alice_step2(a, B)

    # Brute-force: try to find a from A = g^a
    import time
    start = time.time()
    found = None
    for guess in range(1, min(2 ** tiny_bits, dh.q)):
        if mod_exp(dh.g, guess, dh.p) == A:
            found = guess
            break
    elapsed = time.time() - start

    if found is not None:
        K_brute = dh.alice_step2(found, B)

    return {
        'bits': tiny_bits,
        'a': a,
        'brute_force_found': found,
        'correct': found == a if found else False,
        'key_recovered': K_brute == K_real if found else False,
        'time_sec': elapsed,
        'conclusion': f'CDH breakable at {tiny_bits} bits ({elapsed:.3f}s). '
                      f'At 2048 bits, this would take ~2^1024 operations.',
    }


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("Diffie-Hellman Key Exchange")
    print("=" * 60)

    dh = DiffieHellman(bits=64)
    print(f"p = {dh.p}")
    print(f"g = {dh.g}")

    # Normal exchange
    print("\n--- Normal Key Exchange ---")
    result = dh.key_exchange()
    print(f"Alice's A = {result['A']}")
    print(f"Bob's B = {result['B']}")
    print(f"K_Alice = {result['K_alice']}")
    print(f"K_Bob = {result['K_bob']}")
    print(f"Keys match: {result['keys_match']}")

    # MITM
    print("\n--- MITM Attack ---")
    mitm = mitm_attack(dh)
    print(f"Eve has Alice's key: {mitm['eve_has_alice_key']}")
    print(f"Eve has Bob's key: {mitm['eve_has_bob_key']}")
    print(f"Alice & Bob same key: {mitm['alice_bob_same']} (should be False)")
    print(f"Attack success: {mitm['attack_success']}")

    # CDH
    print("\n--- CDH Hardness (tiny params) ---")
    cdh = cdh_hardness_demo(tiny_bits=20)
    print(f"Brute force at {cdh['bits']} bits: {cdh['time_sec']:.3f}s")
    print(f"Key recovered: {cdh['key_recovered']}")
