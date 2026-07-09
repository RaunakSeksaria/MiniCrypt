"""
crypto/modes.py — Modes of Operation (CBC, OFB, CTR)

Implements:
  1. CBC (Cipher Block Chaining): sequential encrypt, parallel decrypt
  2. OFB (Output Feedback): keystream independent of plaintext
  3. Randomized CTR (Counter Mode): fully parallelizable
  4. Unified API: Encrypt(mode, k, M) / Decrypt(mode, k, C)
  5. Attack demos: CBC IV-reuse, OFB keystream-reuse

Dependencies: crypto.prf_ggm (PRF/PRP), crypto.aes, crypto.utils
"""

from crypto.aes import BLOCK_SIZE, aes_decrypt_block, aes_encrypt_block
from crypto.utils import (
    bytes_to_int,
    int_to_bytes,
    pad_pkcs7,
    random_bytes,
    split_blocks,
    to_hex,
    unpad_pkcs7,
    xor_bytes,
)

# ---------------------------------------------------------------------------
# CBC Mode
# ---------------------------------------------------------------------------

def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    CBC Encryption: C_i = E_k(C_{i-1} ⊕ M_i), with C_0 = IV.

    Args:
        key: 16-byte key
        iv: 16-byte initialization vector (must be random per call)
        plaintext: arbitrary-length message (will be PKCS#7 padded)

    Returns:
        Ciphertext (does NOT include IV — caller must store IV separately)
    """
    padded = pad_pkcs7(plaintext, BLOCK_SIZE)
    blocks = split_blocks(padded, BLOCK_SIZE)

    ciphertext = bytearray()
    prev = iv
    for block in blocks:
        xored = xor_bytes(prev, block)
        encrypted = aes_encrypt_block(xored, key)
        ciphertext.extend(encrypted)
        prev = encrypted

    return bytes(ciphertext)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    CBC Decryption: M_i = D_k(C_i) ⊕ C_{i-1}.

    Returns:
        Original plaintext (unpadded).
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must be multiple of block size")

    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    plaintext = bytearray()
    prev = iv

    for block in blocks:
        decrypted = aes_decrypt_block(block, key)
        plaintext.extend(xor_bytes(decrypted, prev))
        prev = block

    return unpad_pkcs7(bytes(plaintext))


# ---------------------------------------------------------------------------
# OFB Mode
# ---------------------------------------------------------------------------

def ofb_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    OFB Encryption: keystream is E_k(E_k(...E_k(IV)...)).
    C_i = M_i ⊕ keystream_i.

    Note: encryption and decryption are the same operation in OFB.
    """
    padded = pad_pkcs7(plaintext, BLOCK_SIZE)
    blocks = split_blocks(padded, BLOCK_SIZE)

    ciphertext = bytearray()
    state = iv
    for block in blocks:
        state = aes_encrypt_block(state, key)  # Generate keystream block
        ciphertext.extend(xor_bytes(state, block))

    return bytes(ciphertext)


def ofb_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    OFB Decryption: identical to encryption (XOR is self-inverse).
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must be multiple of block size")

    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    plaintext = bytearray()
    state = iv

    for block in blocks:
        state = aes_encrypt_block(state, key)
        plaintext.extend(xor_bytes(state, block))

    return unpad_pkcs7(bytes(plaintext))


def ofb_keystream(key: bytes, iv: bytes, num_blocks: int) -> list:
    """
    Pre-compute OFB keystream (independent of plaintext).
    Demonstrates that OFB keystream can be pre-generated.
    """
    keystream = []
    state = iv
    for _ in range(num_blocks):
        state = aes_encrypt_block(state, key)
        keystream.append(state)
    return keystream


# ---------------------------------------------------------------------------
# CTR Mode (Randomized Counter)
# ---------------------------------------------------------------------------

def ctr_encrypt(key: bytes, plaintext: bytes) -> tuple:
    """
    CTR Encryption: C_i = F_k(r+i) ⊕ M_i.
    Nonce r is sampled randomly and included in the output.

    Returns:
        (nonce, ciphertext) where nonce is 16 bytes.
    """
    padded = pad_pkcs7(plaintext, BLOCK_SIZE)
    blocks = split_blocks(padded, BLOCK_SIZE)

    nonce = random_bytes(BLOCK_SIZE)
    nonce_int = bytes_to_int(nonce)

    ciphertext = bytearray()
    for i, block in enumerate(blocks):
        counter = int_to_bytes((nonce_int + i) % (1 << 128), BLOCK_SIZE)
        keystream = aes_encrypt_block(counter, key)
        ciphertext.extend(xor_bytes(keystream, block))

    return nonce, bytes(ciphertext)


def ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    CTR Decryption: M_i = F_k(r+i) ⊕ C_i.
    """
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must be multiple of block size")

    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    nonce_int = bytes_to_int(nonce)

    plaintext = bytearray()
    for i, block in enumerate(blocks):
        counter = int_to_bytes((nonce_int + i) % (1 << 128), BLOCK_SIZE)
        keystream = aes_encrypt_block(counter, key)
        plaintext.extend(xor_bytes(keystream, block))

    return unpad_pkcs7(bytes(plaintext))


# ---------------------------------------------------------------------------
# Unified API
# ---------------------------------------------------------------------------

def encrypt(mode: str, key: bytes, plaintext: bytes,
            iv: bytes = None) -> tuple:
    """
    Unified encryption API.

    Args:
        mode: 'CBC', 'OFB', or 'CTR'
        key: 16-byte key
        plaintext: arbitrary-length message
        iv: IV for CBC/OFB (auto-generated if None)

    Returns:
        (metadata, ciphertext) where metadata is IV/nonce bytes
    """
    mode = mode.upper()
    if mode == 'CBC':
        if iv is None:
            iv = random_bytes(BLOCK_SIZE)
        return iv, cbc_encrypt(key, iv, plaintext)
    elif mode == 'OFB':
        if iv is None:
            iv = random_bytes(BLOCK_SIZE)
        return iv, ofb_encrypt(key, iv, plaintext)
    elif mode == 'CTR':
        return ctr_encrypt(key, plaintext)
    else:
        raise ValueError(f"Unknown mode: {mode}. Use 'CBC', 'OFB', or 'CTR'.")


def decrypt(mode: str, key: bytes, metadata: bytes,
            ciphertext: bytes) -> bytes:
    """
    Unified decryption API.

    Args:
        mode: 'CBC', 'OFB', or 'CTR'
        key: 16-byte key
        metadata: IV (CBC/OFB) or nonce (CTR)
        ciphertext: encrypted message

    Returns:
        Original plaintext
    """
    mode = mode.upper()
    if mode == 'CBC':
        return cbc_decrypt(key, metadata, ciphertext)
    elif mode == 'OFB':
        return ofb_decrypt(key, metadata, ciphertext)
    elif mode == 'CTR':
        return ctr_decrypt(key, metadata, ciphertext)
    else:
        raise ValueError(f"Unknown mode: {mode}.")


# ---------------------------------------------------------------------------
# Attack Demos
# ---------------------------------------------------------------------------

def cbc_iv_reuse_attack() -> dict:
    """
    Demonstrate CBC IV-reuse attack.
    Encrypt two messages with the same IV; if block i matches,
    the ciphertext blocks will match, leaking equality.
    """
    key = random_bytes(BLOCK_SIZE)
    iv = random_bytes(BLOCK_SIZE)

    m1 = b"AAAAAAAAAAAAAAAA" + b"BBBBBBBBBBBBBBBB"  # 2 blocks
    m2 = b"AAAAAAAAAAAAAAAA" + b"CCCCCCCCCCCCCCCC"  # Same first block

    ct1 = cbc_encrypt(key, iv, m1)
    ct2 = cbc_encrypt(key, iv, m2)

    blocks1 = split_blocks(ct1, BLOCK_SIZE)
    blocks2 = split_blocks(ct2, BLOCK_SIZE)

    return {
        'message1': m1,
        'message2': m2,
        'iv': to_hex(iv),
        'ct1_blocks': [to_hex(b) for b in blocks1],
        'ct2_blocks': [to_hex(b) for b in blocks2],
        'block0_match': blocks1[0] == blocks2[0],  # Should be True (same first block + same IV)
        'block1_match': blocks1[1] == blocks2[1],  # Should be False
        'vulnerability': 'Same IV + same first block → identical first ciphertext block',
    }


def ofb_keystream_reuse_attack() -> dict:
    """
    Demonstrate OFB keystream-reuse attack.
    Encrypt two messages with the same IV → XOR ciphertexts = XOR plaintexts.
    """
    key = random_bytes(BLOCK_SIZE)
    iv = random_bytes(BLOCK_SIZE)

    m1 = b"Secret message!!"  # 16 bytes
    m2 = b"Another secret!!"  # 16 bytes

    ct1 = ofb_encrypt(key, iv, m1)
    ct2 = ofb_encrypt(key, iv, m2)

    # XOR the ciphertexts — should give XOR of plaintexts
    ct_xor = xor_bytes(ct1[:BLOCK_SIZE], ct2[:BLOCK_SIZE])
    pt_xor = xor_bytes(m1, m2)

    return {
        'message1': m1,
        'message2': m2,
        'ct_xor': to_hex(ct_xor),
        'pt_xor': to_hex(pt_xor),
        'xor_match': ct_xor == pt_xor,  # Should be True!
        'vulnerability': 'Same IV → same keystream → C1⊕C2 = M1⊕M2',
    }


def bit_flip_error_propagation() -> dict:
    """
    Demonstrate error propagation patterns in each mode.
    Flip one bit in a ciphertext block and observe which plaintext blocks change.
    """
    key = random_bytes(BLOCK_SIZE)
    msg = b"Block zero here!" + b"Block one here!!" + b"Block two here!!"  # 3 blocks exactly

    results = {}
    for mode in ['CBC', 'OFB', 'CTR']:
        iv_or_nonce, ct = encrypt(mode, key, msg)
        original_pt = decrypt(mode, key, iv_or_nonce, ct)

        # Flip bit 0 of ciphertext block 1 (second block)
        ct_modified = bytearray(ct)
        ct_modified[BLOCK_SIZE] ^= 0x01  # Flip first bit of block 1
        ct_modified = bytes(ct_modified)

        try:
            modified_pt = decrypt(mode, key, iv_or_nonce, ct_modified)
            corrupted = []
            for i in range(3):
                orig_block = original_pt[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
                mod_block = modified_pt[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
                if i*BLOCK_SIZE < len(modified_pt):
                    mod_block = modified_pt[i*BLOCK_SIZE:min((i+1)*BLOCK_SIZE, len(modified_pt))]
                    if len(orig_block) == len(mod_block) and orig_block != mod_block:
                        corrupted.append(i)
            results[mode] = {'corrupted_blocks': corrupted}
        except Exception as e:
            results[mode] = {'error': str(e)}

    return results


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("Modes of Operation")
    print("=" * 60)

    key = random_bytes(BLOCK_SIZE)

    # Test all modes with various message lengths
    test_messages = [
        b"Short",                           # Sub-block
        b"Exactly16bytes!!",                 # One block
        b"A longer message spanning multiple blocks for testing purposes!!",
    ]

    for mode in ['CBC', 'OFB', 'CTR']:
        print(f"\n--- {mode} Mode ---")
        for msg in test_messages:
            iv_or_nonce, ct = encrypt(mode, key, msg)
            pt = decrypt(mode, key, iv_or_nonce, ct)
            ok = "✓" if pt == msg else "✗"
            print(f"  {ok} {len(msg):2d}B → {len(ct):2d}B → '{pt[:30].decode(errors='replace')}...'")

    # Attack demos
    print("\n--- CBC IV-Reuse Attack ---")
    attack = cbc_iv_reuse_attack()
    print(f"  Block 0 match (same plaintext + IV): {attack['block0_match']}")
    print(f"  Block 1 match (different plaintext): {attack['block1_match']}")

    print("\n--- OFB Keystream-Reuse Attack ---")
    attack = ofb_keystream_reuse_attack()
    print(f"  C1⊕C2 == M1⊕M2: {attack['xor_match']}")
    print(f"  {attack['vulnerability']}")

    print("\n--- Error Propagation ---")
    props = bit_flip_error_propagation()
    for mode, result in props.items():
        print(f"  {mode}: corrupted blocks = {result.get('corrupted_blocks', result.get('error'))}")
