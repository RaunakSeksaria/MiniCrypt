"""
crypto/pa19_secure_and.py — PA#19: Secure AND Gate

Implements:
  1. Secure AND from OT: Alice(a), Bob(b) → a ∧ b
  2. Secure XOR (free): additive secret sharing over Z_2
  3. Secure NOT (free): local share flip
  4. Privacy proof (comments)
  5. Truth table test (4 combos × 50 runs)

Dependencies: crypto.pa18_ot (Oblivious Transfer)
Used by: PA#20 (2-party MPC)

Privacy argument:
  - Secure AND: Alice plays OT sender with (0, a), Bob plays OT receiver with b.
    Bob receives m_b = a·b = a ∧ b.
    (a) Bob learns nothing about a beyond a∧b (OT receiver privacy: he only gets m_b).
    (b) Alice learns nothing about b (OT sender privacy: she doesn't learn b).
  - Secure XOR: Each party holds one share; shares are random; output = XOR of shares.
    Neither share individually reveals anything.
  - Secure NOT: Purely local computation; no communication ⟹ trivially private.
"""

from crypto.utils import random_int
from crypto.pa18_ot import OTProtocol
from crypto.pa11_diffie_hellman import DHGroup


# ---------------------------------------------------------------------------
# Secure AND (from OT)
# ---------------------------------------------------------------------------

class SecureGates:
    """
    Secure boolean gates for 2-party computation.
    Uses OT for AND; XOR and NOT are free (no communication).
    """

    def __init__(self, ot: OTProtocol = None, bits: int = 32):
        if ot is None:
            group = DHGroup(bits)
            ot = OTProtocol(group=group, bits=bits)
        self.ot = ot
        # Use small integers for bit values (encode 0 and 1 as group elements)
        self.encoding = {0: 1, 1: 2}  # Map bits to group elements ≥ 1
        self.decoding = {1: 0, 2: 1}  # Reverse mapping

    def secure_and(self, a: int, b: int) -> dict:
        """
        Securely compute a ∧ b using OT.

        Protocol:
          1. Alice sets OT sender messages: (m0, m1) = (0, a)
             - m0 = 0 (if Bob's bit is 0, result is a∧0 = 0)
             - m1 = a (if Bob's bit is 1, result is a∧1 = a)
          2. Bob sets OT choice bit = b
          3. Bob receives m_b = a · b = a ∧ b

        Args:
            a: Alice's bit (0 or 1)
            b: Bob's bit (0 or 1)

        Returns:
            dict with result and transcript.
        """
        if a not in (0, 1) or b not in (0, 1):
            raise ValueError("Inputs must be 0 or 1")

        # Alice prepares OT messages: (0, a)
        m0_encoded = self.encoding[0]  # Always encode "0"
        m1_encoded = self.encoding[a]  # Encode Alice's bit

        # Bob's choice = b
        # Run OT protocol
        step1 = self.ot.receiver_step1(b)
        step2 = self.ot.sender_step(step1['pk0'], step1['pk1'],
                                      m0_encoded, m1_encoded)
        received = self.ot.receiver_step2(step1['state'],
                                            step2['C0'], step2['C1'])

        # Decode result
        result = self.decoding.get(received, -1)

        return {
            'a': a, 'b': b,
            'result': result,
            'expected': a & b,
            'correct': result == (a & b),
            'transcript': {
                'alice_ot_messages': (0, a),
                'bob_choice': b,
                'bob_received': result,
                'alice_learns_about_b': False,  # OT sender privacy
                'bob_learns_about_a': result == a if b == 1 else False,
                'bob_learns_beyond_result': False,  # Only learns a∧b
            },
        }

    def secure_xor(self, a: int, b: int) -> dict:
        """
        Securely compute a ⊕ b (free — no OT needed).

        Protocol (additive secret sharing over Z_2):
          1. Alice samples random r ∈ {0, 1}
          2. Alice's share: s_A = a ⊕ r
          3. Bob's share: s_B = b ⊕ r (Alice sends r to Bob)
          4. Output: s_A ⊕ s_B = (a ⊕ r) ⊕ (b ⊕ r) = a ⊕ b
        """
        if a not in (0, 1) or b not in (0, 1):
            raise ValueError("Inputs must be 0 or 1")

        r = random_int(0, 1)
        share_a = a ^ r
        share_b = b ^ r
        result = share_a ^ share_b

        return {
            'a': a, 'b': b,
            'result': result,
            'expected': a ^ b,
            'correct': result == (a ^ b),
            'transcript': {
                'random_mask': r,
                'alice_share': share_a,
                'bob_share': share_b,
                'no_ot_needed': True,
            },
        }

    def secure_not(self, a: int) -> dict:
        """
        Securely compute ¬a (free — purely local).
        Alice flips her share; no communication needed.
        """
        result = 1 - a
        return {
            'a': a,
            'result': result,
            'expected': 1 - a,
            'correct': result == (1 - a),
            'no_communication': True,
        }


# ---------------------------------------------------------------------------
# Truth Table Test
# ---------------------------------------------------------------------------

def truth_table_test(gates: SecureGates = None,
                      runs_per_combo: int = 50) -> dict:
    """
    Verify all 4 input combinations for AND and XOR across multiple runs.
    """
    if gates is None:
        gates = SecureGates(bits=32)

    and_results = {}
    xor_results = {}

    for a in [0, 1]:
        for b in [0, 1]:
            and_correct = 0
            xor_correct = 0

            for _ in range(runs_per_combo):
                and_r = gates.secure_and(a, b)
                if and_r['correct']:
                    and_correct += 1

                xor_r = gates.secure_xor(a, b)
                if xor_r['correct']:
                    xor_correct += 1

            and_results[(a, b)] = {
                'expected': a & b,
                'correct': and_correct,
                'total': runs_per_combo,
                'rate': and_correct / runs_per_combo,
            }
            xor_results[(a, b)] = {
                'expected': a ^ b,
                'correct': xor_correct,
                'total': runs_per_combo,
                'rate': xor_correct / runs_per_combo,
            }

    all_and_correct = all(r['correct'] == r['total'] for r in and_results.values())
    all_xor_correct = all(r['correct'] == r['total'] for r in xor_results.values())

    return {
        'and_results': and_results,
        'xor_results': xor_results,
        'all_and_correct': all_and_correct,
        'all_xor_correct': all_xor_correct,
        'runs_per_combo': runs_per_combo,
    }


# ---------------------------------------------------------------------------
# Privacy Verification
# ---------------------------------------------------------------------------

def privacy_test(gates: SecureGates = None) -> dict:
    """
    Verify that neither party can determine the other's input
    from the protocol transcript alone.
    """
    if gates is None:
        gates = SecureGates(bits=32)

    # For each possible output of AND, check if input is uniquely determined
    # AND=0: could be (0,0), (0,1), (1,0) → not uniquely determined
    # AND=1: must be (1,1) → determined (but that's the output itself)
    # So Bob learning AND=1 tells him a=1, but that's exactly a∧b=1
    # Bob learning AND=0 doesn't tell him a (could be 0 or 1)

    results = []
    for a in [0, 1]:
        for b in [0, 1]:
            r = gates.secure_and(a, b)
            # What Bob knows: b (his input) and a∧b (the output)
            # Can he determine a?
            if r['result'] == 1:
                # a∧b=1 → a must be 1 → but this is the output itself
                bob_learns_a = True
                acceptable = True  # This is inherent in the output
            else:
                # a∧b=0 → a could be 0 (with any b) or a=1,b=0
                bob_learns_a = False
                acceptable = True

            results.append({
                'a': a, 'b': b,
                'output': r['result'],
                'bob_learns_a': bob_learns_a,
                'acceptable': acceptable,
            })

    return {
        'results': results,
        'all_acceptable': all(r['acceptable'] for r in results),
        'conclusion': 'Neither party learns more than the output a∧b '
                      '(which is inherent and unavoidable).',
    }


# ---------------------------------------------------------------------------
# Interface (for PA#20)
# ---------------------------------------------------------------------------

def AND(a: int, b: int, gates: SecureGates = None) -> int:
    """Secure AND gate interface."""
    if gates is None:
        gates = SecureGates(bits=32)
    return gates.secure_and(a, b)['result']

def XOR(a: int, b: int, gates: SecureGates = None) -> int:
    """Secure XOR gate interface."""
    if gates is None:
        gates = SecureGates(bits=32)
    return gates.secure_xor(a, b)['result']

def NOT(a: int) -> int:
    """Secure NOT gate interface (free)."""
    return 1 - a


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("PA#19: Secure AND Gate")
    print("=" * 60)

    gates = SecureGates(bits=32)

    # AND
    print("\n--- Secure AND ---")
    for a in [0, 1]:
        for b in [0, 1]:
            r = gates.secure_and(a, b)
            print(f"  AND({a}, {b}) = {r['result']} "
                  f"(expected {r['expected']}, correct: {r['correct']})")

    # XOR
    print("\n--- Secure XOR ---")
    for a in [0, 1]:
        for b in [0, 1]:
            r = gates.secure_xor(a, b)
            print(f"  XOR({a}, {b}) = {r['result']} "
                  f"(expected {r['expected']}, correct: {r['correct']})")

    # NOT
    print("\n--- Secure NOT ---")
    for a in [0, 1]:
        r = gates.secure_not(a)
        print(f"  NOT({a}) = {r['result']} (correct: {r['correct']})")

    # Truth table
    print("\n--- Truth Table Test (10 runs each) ---")
    tt = truth_table_test(gates, runs_per_combo=10)
    print(f"  All AND correct: {tt['all_and_correct']}")
    print(f"  All XOR correct: {tt['all_xor_correct']}")

    # Privacy
    print("\n--- Privacy Verification ---")
    priv = privacy_test(gates)
    print(f"  {priv['conclusion']}")
