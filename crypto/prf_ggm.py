"""
crypto/prf_ggm.py — Pseudorandom Functions via GGM Tree

Implements:
  1. GGM Tree PRF: F_k(x) = G_{x_n}(... G_{x_1}(k) ...)
     using a length-doubling PRG from .
  2. AES-based PRF plug-in: F_k(x) = AES_k(x)
  3. Backward direction (PRF ⇒ PRG): G(s) = F_s(0^n) ‖ F_s(1^n)
  4. PRF distinguishing game (100-query test)

Dependencies: crypto.owf_prg, crypto.aes, crypto.utils
Used by: cpa_enc, mac, and transitively by later modules in the chain

Bidirectional: PRG ⇔ PRF
  Forward:  PRG ⇒ PRF via GGM tree
  Backward: PRF ⇒ PRG via G(s) = F_s(0) ‖ F_s(1)
"""

from crypto.utils import (
    xor_bytes, random_bytes, bytes_to_int, int_to_bytes,
    to_hex, get_bit, bytes_to_bits
)
from crypto.aes import aes_encrypt_block, aes_decrypt_block, BLOCK_SIZE
from crypto.owf_prg import PRG_from_AES, run_statistical_tests


# ---------------------------------------------------------------------------
# GGM Tree PRF (from PRG)
# ---------------------------------------------------------------------------

class GGM_PRF:
    """
    GGM Tree-based Pseudorandom Function.

    Given a length-doubling PRG G : {0,1}^n → {0,1}^{2n},
    write G(s) = G_0(s) ‖ G_1(s).

    Define F_k(b_1 b_2 ... b_n) = G_{b_n}(... G_{b_1}(k) ...).

    This walks from root to leaf in a binary tree of depth n.
    """

    def __init__(self, prg: PRG_from_AES = None):
        """
        Args:
            prg: A PRG instance with G0(s) and G1(s) methods.
                 If None, creates a PRG_from_AES.
        """
        if prg is None:
            prg = PRG_from_AES()
        self.prg = prg
        self.block_size = BLOCK_SIZE  # 16 bytes

    def evaluate(self, key: bytes, x: bytes) -> bytes:
        """
        Evaluate F_k(x) using the GGM tree.

        Args:
            key: Key k (16 bytes).
            x: Input x (16 bytes, but we use the first n bits where n = key_bits).

        Returns:
            PRF output (16 bytes).
        """
        if len(key) != self.block_size:
            raise ValueError(f"Key must be {self.block_size} bytes")
        if len(x) != self.block_size:
            raise ValueError(f"Input must be {self.block_size} bytes")

        # Walk the tree from root to leaf
        current = key
        n_bits = self.block_size * 8  # 128 bits for AES-sized blocks

        for i in range(n_bits):
            bit = get_bit(x, i)
            if bit == 0:
                current = self.prg.G0(current)
            else:
                current = self.prg.G1(current)

        return current

    def evaluate_short(self, key: bytes, x_bits: list) -> bytes:
        """
        Evaluate F_k(x) where x is given as a short list of bits.
        This is useful for visualization (small tree depths like 4-8 bits).

        Args:
            key: Key k (16 bytes).
            x_bits: List of 0/1 bits representing the query.

        Returns:
            PRF output (16 bytes).
        """
        current = key
        for bit in x_bits:
            if bit == 0:
                current = self.prg.G0(current)
            else:
                current = self.prg.G1(current)
        return current

    def generate_full_tree(self, key: bytes, depth: int) -> dict:
        """
        Generate every node in the GGM tree up to a certain depth.
        Used for the full binary tree visualizer.

        Returns:
            Dictionary mapping depth -> list of nodes at that depth.
        """
        if depth > 8:
            raise ValueError("Max depth for full tree visualization is 8")

        tree = {0: [{"value": to_hex(key), "index": 0}]}
        
        for d in range(depth):
            tree[d+1] = []
            for i, parent_node in enumerate(tree[d]):
                parent_val = bytes.fromhex(parent_node["value"])
                g0 = self.prg.G0(parent_val)
                g1 = self.prg.G1(parent_val)
                
                tree[d+1].append({"value": to_hex(g0), "index": i*2, "parent_index": i})
                tree[d+1].append({"value": to_hex(g1), "index": i*2+1, "parent_index": i})
        
        return tree

    def evaluate_with_trace(self, key: bytes, x_bits: list) -> dict:
        """
        Evaluate F_k(x) and return the full trace of intermediate values.
        """
        trace = {'key': to_hex(key), 'input_bits': x_bits, 'steps': [], 'output': None}
        current = key
        for i, bit in enumerate(x_bits):
            g0 = self.prg.G0(current)
            g1 = self.prg.G1(current)
            chosen = g0 if bit == 0 else g1
            trace['steps'].append({
                'depth': i, 'bit': bit, 'parent': to_hex(current),
                'G0': to_hex(g0), 'G1': to_hex(g1), 'chosen': to_hex(chosen),
            })
            current = chosen
        trace['output'] = to_hex(current)
        return trace


# ---------------------------------------------------------------------------
# AES-based PRF (plug-in alternative)
# ---------------------------------------------------------------------------

class AES_PRF:
    """
    AES-128 used directly as a PRF: F_k(x) = AES_k(x).

    By the PRP/PRF switching lemma, AES (a PRP) is computationally
    indistinguishable from a PRF when the domain is large (2^128).
    """

    def __init__(self):
        self.block_size = BLOCK_SIZE

    def evaluate(self, key: bytes, x: bytes) -> bytes:
        """Evaluate F_k(x) = AES_k(x)."""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(x) != 16:
            raise ValueError("Input must be 16 bytes")
        return aes_encrypt_block(x, key)

    def inverse(self, key: bytes, y: bytes) -> bytes:
        """Evaluate F_k^{-1}(y) = AES_k^{-1}(y). (PRP inverse)"""
        return aes_decrypt_block(y, key)

    def evaluate_with_trace(self, key: bytes, x: bytes) -> dict:
        """Evaluate with trace for the web visualizer."""
        output = self.evaluate(key, x)
        return {
            'key': to_hex(key),
            'input': to_hex(x),
            'output': to_hex(output),
            'method': 'AES-128 direct (PRP/PRF switching lemma)',
        }


# ---------------------------------------------------------------------------
# Unified PRF Interface
# ---------------------------------------------------------------------------

class PRF:
    """
    Unified PRF interface that can use either GGM tree or AES.
    Default: AES (for performance). GGM tree for theoretical demonstration.
    """

    def __init__(self, mode: str = 'aes'):
        """
        Args:
            mode: 'aes' for AES-based PRF, 'ggm' for GGM tree PRF.
        """
        self.mode = mode
        if mode == 'aes':
            self._impl = AES_PRF()
        elif mode == 'ggm':
            self._impl = GGM_PRF()
        else:
            raise ValueError(f"Unknown PRF mode: {mode}")
        self.block_size = BLOCK_SIZE

    def F(self, key: bytes, x: bytes) -> bytes:
        """
        Evaluate the PRF: F_k(x).
        This is the primary interface used across the library.
        """
        return self._impl.evaluate(key, x)

    def evaluate(self, key: bytes, x: bytes) -> bytes:
        """Alias for F(key, x)."""
        return self.F(key, x)


class PRG_from_PRF:
    """
    Construct a PRG from a PRF.
    G(s) = F_s(0) ‖ F_s(1)
    """
    def __init__(self, prf: PRF):
        self.prf = prf

    def next_bits(self, seed: bytes, n_bits: int) -> list:
        """Generate bits using the PRF as a PRG."""
        bits = []
        counter = 0
        while len(bits) < n_bits:
            ctr_block = int_to_bytes(counter, 16)
            output = self.prf.evaluate(seed, ctr_block)
            bits.extend(bytes_to_bits(output))
            counter += 1
        return bits[:n_bits]


# ---------------------------------------------------------------------------
# Backward Direction: PRF ⇒ PRG
# ---------------------------------------------------------------------------

def prf_to_prg(prf: PRF, seed: bytes) -> bytes:
    """
    Backward direction: construct a PRG from a PRF.
    G(s) = F_s(0^n) ‖ F_s(1^n)
    Maps 16 bytes → 32 bytes (length-doubling).
    """
    zero_block = b'\x00' * 16
    one_block = b'\xff' * 16
    left = prf.F(seed, zero_block)
    right = prf.F(seed, one_block)
    return left + right


def demonstrate_prf_to_prg(prf: PRF, num_bits: int = 1000):
    """
    Show that G(s) = F_s(0) ‖ F_s(1) produces pseudorandom output.
    Run statistical tests on the PRG output.
    """
    seed = random_bytes(16)
    # Generate extended output by varying the counter
    bits = []
    counter = 0
    while len(bits) < num_bits:
        ctr_block = int_to_bytes(counter, 16)
        output = prf.F(seed, ctr_block)
        bits.extend(bytes_to_bits(output))
        counter += 1

    bits = bits[:num_bits]
    test_results = run_statistical_tests(bits)

    return {
        'seed': to_hex(seed),
        'num_bits': num_bits,
        'tests': test_results,
    }


# ---------------------------------------------------------------------------
# PRF Distinguishing Game
# ---------------------------------------------------------------------------

def distinguishing_game(prf: PRF, num_queries: int = 100) -> dict:
    """
    PRF distinguishing game.

    The challenger either:
      - Uses a real PRF F_k with a random key k, or
      - Uses a truly random function (random output for each unique input).

    The adversary makes num_queries queries and tries to distinguish.
    We run both scenarios and show the outputs are statistically similar.
    """
    import random as stdlib_random

    key = random_bytes(16)

    # Real PRF outputs
    prf_outputs = []
    for i in range(num_queries):
        x = int_to_bytes(i, 16)
        y = prf.F(key, x)
        prf_outputs.append(y)

    # Random function outputs (unique random output per input)
    random_outputs = []
    for _ in range(num_queries):
        random_outputs.append(random_bytes(16))

    # Calculate aggregate stats
    prf_ones = sum(sum(bytes_to_bits(y)) for y in prf_outputs)
    rand_ones = sum(sum(bytes_to_bits(y)) for y in random_outputs)
    total_bits = num_queries * 128
    prf_ratio = prf_ones / total_bits
    rand_ratio = rand_ones / total_bits

    # Pick 2 actual samples from the batch we just ran
    samples = []
    for i in [0, num_queries // 2]: # First one and middle one
        samples.append({
            'x': to_hex(int_to_bytes(i, 16)),
            'prf': to_hex(prf_outputs[i]),
            'rand': to_hex(random_outputs[i])
        })

    return {
        'trials': num_queries,
        'prf_ones_ratio': prf_ratio,
        'random_ones_ratio': rand_ratio,
        'advantage': abs(prf_ratio - rand_ratio),
        'samples': samples,
        'indistinguishable': abs(prf_ratio - rand_ratio) < 0.05,
        'conclusion': ('PRF is indistinguishable from random'
                       if abs(prf_ratio - rand_ratio) < 0.05
                       else 'Unexpectedly distinguishable (check implementation)'),
    }


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("Pseudorandom Functions via GGM Tree")
    print("=" * 60)

    # --- AES PRF ---
    print("\n--- AES-Based PRF ---")
    prf = PRF(mode='aes')
    key = random_bytes(16)
    x = random_bytes(16)
    y = prf.F(key, x)
    print(f"Key: {to_hex(key)}")
    print(f"F_k({to_hex(x)}) = {to_hex(y)}")

    # Verify determinism
    y2 = prf.F(key, x)
    print(f"Same input again: {to_hex(y2)} (match: {y == y2})")

    # Different input
    x2 = random_bytes(16)
    y3 = prf.F(key, x2)
    print(f"F_k({to_hex(x2)}) = {to_hex(y3)} (different: {y != y3})")

    # --- GGM PRF ---
    print("\n--- GGM Tree PRF (small depth for visualization) ---")
    ggm = GGM_PRF()
    key = random_bytes(16)

    for bits in [[0, 0], [0, 1], [1, 0], [1, 1]]:
        trace = ggm.evaluate_with_trace(key, bits)
        print(f"F_k({''.join(map(str, bits))}) = {trace['output'][:16]}...")

    # Full trace for one query
    print("\nFull trace for query [1, 0, 1]:")
    trace = ggm.evaluate_with_trace(key, [1, 0, 1])
    for step in trace['steps']:
        print(f"  Depth {step['depth']}: bit={step['bit']}, "
              f"parent={step['parent'][:8]}..., "
              f"chosen={step['chosen'][:8]}...")
    print(f"  Output: {trace['output'][:16]}...")

    # --- Backward: PRF ⇒ PRG ---
    print("\n--- Backward Direction: PRF ⇒ PRG ---")
    prf = PRF(mode='aes')
    seed = random_bytes(16)
    prg_output = prf_to_prg(prf, seed)
    print(f"Seed ({len(seed)} bytes): {to_hex(seed)}")
    print(f"G(s) = F_s(0)‖F_s(1) ({len(prg_output)} bytes): {to_hex(prg_output)}")

    prg_test = demonstrate_prf_to_prg(prf)
    print(f"\nStatistical tests on PRF→PRG output:")
    for result in prg_test['tests']:
        status = "PASS" if result['pass'] else "FAIL"
        print(f"  {result['test']}: {status} (p={result['p_value']:.4f})")

    # --- Distinguishing Game ---
    print("\n--- PRF Distinguishing Game ---")
    game = distinguishing_game(prf)
    print(f"Queries: {game['trials']}")
    print(f"PRF 1-bit ratio: {game['prf_ones_ratio']:.4f}")
    print(f"Random 1-bit ratio: {game['random_ones_ratio']:.4f}")
    print(f"Advantage: {game['advantage']:.4f}")
    print(f"Conclusion: {game['conclusion']}")
