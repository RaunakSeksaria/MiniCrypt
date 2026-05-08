"""
crypto/pa07_merkle_damgard.py — PA#7: Merkle-Damgård Transform

Implements:
  1. Generic MerkleDamgard(compress, IV, block_size) framework
  2. MD-strengthening padding (M ‖ 1 ‖ 0* ‖ ⟨|M|⟩₆₄)
  3. Dummy XOR-based compression for testing
  4. Collision propagation demo

Dependencies: crypto.utils
Used by: PA#8 (DLP-CRHF), PA#10 (HMAC)
"""

from crypto.utils import int_to_bytes, bytes_to_int, xor_bytes, to_hex


# ---------------------------------------------------------------------------
# Merkle-Damgård Transform
# ---------------------------------------------------------------------------

class MerkleDamgard:
    """
    Generic Merkle-Damgård hash function framework.

    Given:
      - A compression function h: {0,1}^{n+b} → {0,1}^n
        (takes chaining value CV of n bytes + block of b bytes → n bytes)
      - An initialization vector IV of n bytes
      - A block size b

    Produces a hash function for arbitrary-length messages.
    """

    def __init__(self, compress, iv: bytes, block_size: int):
        """
        Args:
            compress: Compression function f(chaining_value: bytes, block: bytes) → bytes.
                      Must accept (n-byte CV, b-byte block) and return n-byte CV.
            iv: Initialization vector (n bytes).
            block_size: Block size b in bytes.
        """
        self.compress = compress
        self.iv = iv
        self.block_size = block_size
        self.digest_size = len(iv)  # Output size = CV size

    def pad(self, message: bytes) -> bytes:
        """
        Apply Merkle-Damgård strengthening padding.

        M ‖ 1 ‖ 0* ‖ ⟨|M|⟩₆₄

        Appends:
          - A single 0x80 byte (the '1' bit followed by 7 zero bits)
          - Zero bytes until the length is ≡ (block_size - 8) mod block_size
          - The original message length as a 64-bit big-endian integer
        """
        msg_len = len(message)
        msg_len_bits = msg_len * 8

        # Append 0x80
        padded = bytearray(message) + bytearray([0x80])

        # Pad with zeros until length ≡ block_size - 8 (mod block_size)
        while (len(padded) + 8) % self.block_size != 0:
            padded.append(0x00)

        # Append 64-bit big-endian length
        padded.extend(msg_len_bits.to_bytes(8, byteorder='big'))

        return bytes(padded)

    def hash(self, message: bytes) -> bytes:
        """
        Hash an arbitrary-length message.

        1. Apply MD-strengthening padding.
        2. Split into blocks.
        3. Iterate compression function: z_i = compress(z_{i-1}, M_i).
        4. Return final chaining value.
        """
        padded = self.pad(message)

        # Split into blocks
        blocks = [padded[i:i + self.block_size]
                  for i in range(0, len(padded), self.block_size)]

        # Iterate compression
        cv = self.iv
        for block in blocks:
            cv = self.compress(cv, block)

        return cv

    def hash_with_trace(self, message: bytes) -> dict:
        """
        Hash with full trace of intermediate values (for web visualizer).
        """
        padded = self.pad(message)
        blocks = [padded[i:i + self.block_size]
                  for i in range(0, len(padded), self.block_size)]

        trace = {
            'message': to_hex(message),
            'padded': to_hex(padded),
            'num_blocks': len(blocks),
            'steps': [],
            'digest': None,
        }

        # Calculate where message data ends
        msg_len = len(message)
        
        cv = self.iv
        for i, block in enumerate(blocks):
            new_cv = self.compress(cv, block)
            
            # Determine label
            start_offset = i * self.block_size
            if start_offset + self.block_size <= msg_len:
                label = "Message Data"
            elif start_offset < msg_len:
                label = "Data + Padding"
            elif i == len(blocks) - 1:
                label = "MD Length"
            else:
                label = "Padding"

            trace['steps'].append({
                'block_index': i,
                'block': to_hex(block),
                'label': label,
                'cv_in': to_hex(cv),
                'cv_out': to_hex(new_cv),
            })
            cv = new_cv

        trace['digest'] = to_hex(cv)
        return trace


# ---------------------------------------------------------------------------
# Dummy XOR-based Compression (for testing)
# ---------------------------------------------------------------------------

def xor_compress(cv: bytes, block: bytes) -> bytes:
    """
    Simple XOR-based compression function for testing.
    h(cv, block) = cv ⊕ block[:len(cv)] ⊕ block[len(cv):]

    This is NOT collision-resistant — it's purely for testing the MD framework.
    """
    n = len(cv)
    b = len(block)

    # XOR CV with parts of the block
    result = bytearray(cv)
    for i in range(b):
        result[i % n] ^= block[i]

    return bytes(result)


def create_toy_hash(digest_size: int = 4, block_size: int = 8):
    """
    Create a toy hash function using XOR compression.
    Default: 4-byte (32-bit) digest, 8-byte blocks.
    """
    iv = b'\x00' * digest_size
    return MerkleDamgard(xor_compress, iv, block_size)


# ---------------------------------------------------------------------------
# Collision Propagation Demo
# ---------------------------------------------------------------------------

def collision_propagation_demo() -> dict:
    """
    Show the reduction: a collision in the full MD hash implies
    a collision in the compression function.

    We use the toy XOR compress which has trivial collisions
    to demonstrate the principle.
    """
    toy_hash = create_toy_hash(digest_size=2, block_size=4)

    # Find two messages that collide under the toy hash
    # With 2-byte digest, collisions are easy to find
    from crypto.utils import random_bytes
    seen = {}
    collision = None

    for _ in range(1000):
        msg = random_bytes(4)  # Short messages
        h = toy_hash.hash(msg)
        if h in seen and seen[h] != msg:
            collision = (seen[h], msg, h)
            break
        seen[h] = msg

    if collision is None:
        return {'found': False}

    m1, m2, h = collision
    trace1 = toy_hash.hash_with_trace(m1)
    trace2 = toy_hash.hash_with_trace(m2)

    return {
        'found': True,
        'message1': to_hex(m1),
        'message2': to_hex(m2),
        'digest': to_hex(h),
        'trace1_steps': len(trace1['steps']),
        'trace2_steps': len(trace2['steps']),
        'implication': 'Collision in H ⟹ collision in compress function h',
    }


# ---------------------------------------------------------------------------
# Interface (for PA#8)
# ---------------------------------------------------------------------------

def hash_message(message: bytes, compress, iv: bytes = None,
                 block_size: int = 16) -> bytes:
    """
    Convenience function: hash a message using a given compression function.
    """
    if iv is None:
        iv = b'\x00' * 16  # Default IV
    md = MerkleDamgard(compress, iv, block_size)
    return md.hash(message)


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("PA#7: Merkle-Damgård Transform")
    print("=" * 60)

    # Toy hash
    print("\n--- Toy XOR-based Hash ---")
    toy = create_toy_hash()
    for msg in [b"", b"Hello!", b"Hello!!", b"A message that is definitely longer than one block"]:
        h = toy.hash(msg)
        print(f"H({msg[:30]!r}...) = {to_hex(h)}")

    # Trace
    print("\n--- Hash Trace ---")
    trace = toy.hash_with_trace(b"Test message")
    print(f"Message: {trace['message']}")
    print(f"Padded: {trace['padded']}")
    print(f"Blocks: {trace['num_blocks']}")
    for step in trace['steps']:
        print(f"  Block {step['block_index']}: "
              f"CV={step['cv_in']} → {step['cv_out']}")
    print(f"Digest: {trace['digest']}")

    # Collision propagation
    print("\n--- Collision Propagation Demo ---")
    demo = collision_propagation_demo()
    if demo['found']:
        print(f"Collision found!")
        print(f"  M1 = {demo['message1']}")
        print(f"  M2 = {demo['message2']}")
        print(f"  H(M1) = H(M2) = {demo['digest']}")
        print(f"  {demo['implication']}")
    else:
        print("No collision found in 1000 tries (unlikely with 2-byte digest)")
