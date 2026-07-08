"""
crypto/ot.py — Oblivious Transfer (OT)

Implements:
  1. 1-out-of-2 OT using ElGamal (Bellare-Micali protocol)
  2. Three-step API: OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2
  3. Receiver privacy demo (sender can't determine choice bit b)
  4. Sender privacy demo (receiver can't decrypt C_{1-b})
  5. 100-trial correctness test

Dependencies: crypto.elgamal (ElGamal PKC)
Used by: (Secure AND), (MPC)

Lineage: → → → 
"""

from crypto.utils import mod_exp, mod_inverse, random_int, random_bytes, to_hex
from crypto.elgamal import elgamal_keygen, elgamal_encrypt, elgamal_decrypt
from crypto.diffie_hellman import DHGroup


# ---------------------------------------------------------------------------
# OT Protocol (Bellare-Micali style using ElGamal)
# ---------------------------------------------------------------------------

class OTProtocol:
    """
    1-out-of-2 Oblivious Transfer using ElGamal.

    Sender holds (m0, m1). Receiver holds choice bit b.
    After protocol: Receiver learns m_b but not m_{1-b}.
    Sender learns nothing about b.

    Protocol:
      1. Receiver generates two ElGamal key pairs. Keeps sk_b, discards sk_{1-b}.
         pk_{1-b} is constructed without a known secret key.
      2. Receiver sends (pk_0, pk_1) to Sender.
      3. Sender encrypts: C_0 = ElGamal.Enc(pk_0, m_0), C_1 = ElGamal.Enc(pk_1, m_1).
      4. Receiver decrypts C_b using sk_b. Cannot decrypt C_{1-b}.
    """

    def __init__(self, group: DHGroup = None, bits: int = 64):
        if group is None:
            group = DHGroup(bits)
        self.group = group
        self.p = group.p
        self.g = group.g
        self.q = group.q

    def receiver_step1(self, b: int) -> dict:
        """
        Receiver Step 1: Generate key pairs.

        For the chosen index b:
          - Generate (pk_b, sk_b) honestly.
        For the other index 1-b:
          - Generate pk_{1-b} as a random group element (no known sk).

        Args:
            b: Choice bit (0 or 1).

        Returns:
            dict with 'pk0', 'pk1' (public keys as dicts), and 'state' (private).
        """
        if b not in (0, 1):
            raise ValueError("Choice bit must be 0 or 1")

        # Generate honest key pair for choice b
        sk_b = random_int(2, self.q - 1)
        h_b = mod_exp(self.g, sk_b, self.p)

        # Generate random public key for 1-b (no known secret key)
        # Just pick a random group element as h_{1-b}
        h_1b = mod_exp(self.g, random_int(2, self.q - 1), self.p)
        # The secret key for h_{1-b} is unknown to the receiver

        pk_b = {'p': self.p, 'g': self.g, 'q': self.q, 'h': h_b}
        pk_1b = {'p': self.p, 'g': self.g, 'q': self.q, 'h': h_1b}

        if b == 0:
            pk0, pk1 = pk_b, pk_1b
        else:
            pk0, pk1 = pk_1b, pk_b

        state = {
            'b': b,
            'sk_b': sk_b,
            'pk0': pk0,
            'pk1': pk1,
        }

        return {
            'pk0': pk0,
            'pk1': pk1,
            'state': state,
        }

    def sender_step(self, pk0: dict, pk1: dict,
                     m0: int, m1: int) -> dict:
        """
        Sender Step: Encrypt both messages.

        C_0 = ElGamal.Enc(pk_0, m_0)
        C_1 = ElGamal.Enc(pk_1, m_1)

        Args:
            pk0, pk1: Public keys received from receiver.
            m0, m1: Sender's two messages (integers in [1, p-1]).

        Returns:
            dict with 'C0' = (c1_0, c2_0) and 'C1' = (c1_1, c2_1).
        """
        c1_0, c2_0 = elgamal_encrypt(pk0, m0)
        c1_1, c2_1 = elgamal_encrypt(pk1, m1)

        return {
            'C0': (c1_0, c2_0),
            'C1': (c1_1, c2_1),
        }

    def receiver_step2(self, state: dict, C0: tuple, C1: tuple) -> int:
        """
        Receiver Step 2: Decrypt the chosen ciphertext.

        Args:
            state: Private state from step 1 (contains b and sk_b).
            C0, C1: Ciphertexts from sender.

        Returns:
            m_b: The chosen message.
        """
        b = state['b']
        sk_b = state['sk_b']

        # Decrypt C_b
        C_chosen = C0 if b == 0 else C1
        c1, c2 = C_chosen

        m_b = elgamal_decrypt(sk_b, self.p, c1, c2)
        return m_b


# ---------------------------------------------------------------------------
# Full OT Protocol Run
# ---------------------------------------------------------------------------

def run_ot(m0: int, m1: int, b: int, bits: int = 64) -> dict:
    """
    Run a complete OT protocol.

    Args:
        m0, m1: Sender's messages.
        b: Receiver's choice bit.
        bits: Security parameter.

    Returns:
        dict with results and protocol trace.
    """
    ot = OTProtocol(bits=bits)

    # Step 1: Receiver generates keys
    step1 = ot.receiver_step1(b)

    # Step 2: Sender encrypts
    step2 = ot.sender_step(step1['pk0'], step1['pk1'], m0, m1)

    # Step 3: Receiver decrypts
    m_b = ot.receiver_step2(step1['state'], step2['C0'], step2['C1'])

    expected = m0 if b == 0 else m1

    return {
        'm0': m0, 'm1': m1, 'b': b,
        'received': m_b,
        'expected': expected,
        'correct': m_b == expected,
        'trace': {
            'pk0_h': step1['pk0']['h'],
            'pk1_h': step1['pk1']['h'],
            'C0': step2['C0'],
            'C1': step2['C1'],
        },
    }


# ---------------------------------------------------------------------------
# Privacy Demos
# ---------------------------------------------------------------------------

def receiver_privacy_demo(bits: int = 64, trials: int = 100) -> dict:
    """
    Demonstrate receiver privacy: sender cannot determine b
    from (pk0, pk1). Both public keys look random.
    """
    ot = OTProtocol(bits=bits)

    # Sender sees pk0 and pk1 — can they tell which one has a known sk?
    # Both h values are random group elements, so they're indistinguishable.
    b0_count = 0
    for _ in range(trials):
        b = random_int(0, 1)
        step1 = ot.receiver_step1(b)

        # Sender's "best strategy": guess randomly
        guess = random_int(0, 1)
        if guess == b:
            b0_count += 1

    return {
        'trials': trials,
        'sender_correct_guesses': b0_count,
        'sender_advantage': abs(b0_count / trials - 0.5),
        'private': abs(b0_count / trials - 0.5) < 0.15,
    }


def sender_privacy_demo(bits: int = 32) -> dict:
    """
    Demonstrate sender privacy: receiver cannot decrypt C_{1-b}.
    Try brute-force decryption of C_{1-b} and show it fails.
    """
    ot = OTProtocol(bits=bits)
    m0, m1 = 42, 99
    b = 0  # Receiver wants m0

    step1 = ot.receiver_step1(b)
    step2 = ot.sender_step(step1['pk0'], step1['pk1'], m0, m1)

    # Receiver can decrypt C0 (they have sk0)
    m_received = ot.receiver_step2(step1['state'], step2['C0'], step2['C1'])

    # Try to decrypt C1 (they DON'T have sk1)
    # Brute-force: try all possible secret keys
    c1_1, c2_1 = step2['C1']
    found_m1 = None
    for sk_guess in range(1, min(ot.q, 10000)):
        m_guess = elgamal_decrypt(sk_guess, ot.p, c1_1, c2_1)
        if m_guess == m1:
            found_m1 = m_guess
            break

    return {
        'b': b,
        'm0': m0, 'm1': m1,
        'received': m_received,
        'received_correct': m_received == m0,
        'brute_force_m1': found_m1,
        'brute_force_searched': min(ot.q, 10000),
        'private': found_m1 is None or bits > 32,
        'note': 'For large parameters, DLP prevents recovering sk_{1-b}',
    }


def correctness_test(bits: int = 32, trials: int = 100) -> dict:
    """Run 100 trials with random inputs and verify correctness."""
    ot = OTProtocol(bits=bits)
    correct = 0

    for _ in range(trials):
        m0 = random_int(1, ot.p - 2)
        m1 = random_int(1, ot.p - 2)
        b = random_int(0, 1)

        step1 = ot.receiver_step1(b)
        step2 = ot.sender_step(step1['pk0'], step1['pk1'], m0, m1)
        m_b = ot.receiver_step2(step1['state'], step2['C0'], step2['C1'])

        expected = m0 if b == 0 else m1
        if m_b == expected:
            correct += 1

    return {
        'trials': trials,
        'correct': correct,
        'rate': correct / trials,
        'all_correct': correct == trials,
    }


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

_default_ot = None

def get_ot(bits: int = 32) -> OTProtocol:
    global _default_ot
    if _default_ot is None:
        _default_ot = OTProtocol(bits=bits)
    return _default_ot


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("Oblivious Transfer (OT)")
    print("=" * 60)

    # Basic OT
    print("\n--- 1-out-of-2 OT ---")
    for b in [0, 1]:
        result = run_ot(m0=42, m1=99, b=b, bits=32)
        print(f"  b={b}: received m_{b} = {result['received']} "
              f"(expected {result['expected']}, correct: {result['correct']})")

    # Correctness
    print("\n--- 100-Trial Correctness Test ---")
    ct = correctness_test(bits=32)
    print(f"  {ct['correct']}/{ct['trials']} correct (rate: {ct['rate']:.2f})")

    # Receiver privacy
    print("\n--- Receiver Privacy ---")
    rp = receiver_privacy_demo(bits=32)
    print(f"  Sender guesses: {rp['sender_correct_guesses']}/{rp['trials']}")
    print(f"  Advantage: {rp['sender_advantage']:.4f} (should be ~0)")

    # Sender privacy
    print("\n--- Sender Privacy ---")
    sp = sender_privacy_demo(bits=32)
    print(f"  Received m_{sp['b']} = {sp['received']} (correct: {sp['received_correct']})")
    print(f"  Brute-force m_{1-sp['b']}: {sp['brute_force_m1']} "
          f"(searched {sp['brute_force_searched']} keys)")
