# 🛡️ PA#1 Master Guide: One-Way Functions & PRGs

Welcome to the definitive guide for **Programming Assignment #1**. This document covers everything from high-level theory to the exact steps needed to demonstrate and defend your implementation.

---

## 📖 1. The Core Theory: Why PA#1 Matters

The goal of PA#1 is to implement and verify the **foundational primitives** of cryptography:
1.  **One-Way Functions (OWF)**: Functions that are easy to compute but hard to invert.
2.  **Pseudorandom Generators (PRG)**: Algorithms that turn a short, truly random "seed" into a long, "random-looking" bitstream.

### The HILL Theorem
Your assignment is based on the **HILL Construction** (Håstad, Impagliazzo, Levin, and Luby), which proves that:
> **"A secure PRG exists if and only if a One-Way Function exists."**

---

## ⚙️ 2. The Implementation (Minicrypt Style)

We implement these primitives using **AES-128** as our building block (no external crypto libraries used).

### A. How we build a OWF from AES (Davies-Meyer)
A block cipher like AES is a *permutation* (reversible). To make it a One-Way Function, we use the **Davies-Meyer** construction:
- **Formula**: `f(k) = AES_k(0) ⊕ k`
- **Theory (The "Why")**: AES is designed to be reversible so we can decrypt. By XORing the key `k` back into the output, we "lock" the function. Even if an attacker "inverts" the AES logic, they still have an unknown `k` XORed in, making inversion computationally infeasible.
- **Code Implementation** (`crypto/aes.py`):
```python
def aes_owf(key: bytes) -> bytes:
    zero_block = b'\x00' * 16
    # 1. Encrypt a block of all zeros using the seed as the key
    encrypted = aes_encrypt_block(zero_block, key)
    # 2. XOR the result with the original key (Davies-Meyer)
    return xor_bytes(encrypted, key)
```

### B. How we build a PRG from AES (Counter Mode)
To expand a 16-byte seed into a long bitstream:
- **Formula**: `G(s) = AES_s(0) ‖ AES_s(1) ‖ AES_s(2) ...`
- **Theory (The "How")**: We use AES in **Counter Mode (CTR)**. We treat the seed as the AES key and encrypt a sequence of numbers (0, 1, 2...). Since every counter value is unique, the output of every AES call is unique and pseudorandom.
- **Code Implementation** (`crypto/pa01_owf_prg.py`):
```python
def generate(self, seed: bytes, output_bytes: int) -> bytes:
    result = bytearray()
    counter = 0
    while len(result) < output_bytes:
        # 1. Convert counter (0, 1, 2...) into a 16-byte block
        ctr_block = int_to_bytes(counter, 16)
        # 2. Encrypt counter using seed as key
        block_output = aes_encrypt_block(ctr_block, seed)
        result.extend(block_output)
        counter += 1
    return bytes(result[:output_bytes])
```

---

## 🧪 3. How to Test (Interactive Demo)

Open the **PA Demos** tab and select **PA#1**.

### Step 1: The "Live" Generation
- **The Slider**: Moving the slider changes the `length` parameter. Watch the "Live PRG Output" update instantly.
- **The Seed**: Change the Hex Seed. Notice how even a 1-bit change in the seed completely flips the output bitstream (the "Avalanche Effect").

### Step 2: 🧪 Randomness Verification
Click the **🧪 Randomness Tests** button. The app runs three NIST-standard tests:
1.  **Monobit Test**: Checks if the number of 0s and 1s is roughly equal.
2.  **Runs Test**: Checks if bits flip too often or too rarely.
3.  **Serial Test**: Checks if 2-bit patterns (00, 01, 10, 11) are distributed evenly.
- **Pass Criteria**: A p-value > 0.01 means the output is statistically indistinguishable from "true" randomness.

### Step 3: 🛡️ One-Wayness Verification (PA#1b)
Click the **🛡️ One-Wayness** button. This demonstrates the **PRG ⇒ OWF** backward reduction.
- **The Adversary**: The server simulates an attacker who is given the PRG output and tries to guess the original seed.
- **The Proof**: You will see **Red Tags** representing "Failed Attempts." Even after 10,000+ guesses, the adversary's success rate is **0.000%**.

---

## 🖥️ 4. Advanced Testing (CLI/Terminal)
If the TA asks to see "the raw data," run this in your terminal:

```bash
# Test the PRG Inversion (One-Wayness)
curl -s -X POST http://127.0.0.1:8000/api/demo \
  -H "Content-Type: application/json" \
  -d '{"pa":1,"params":{"seed":"2b7e151628aed2a6abf7158809cf4f3c","task":"inversion"}}' | jq
```

---

## 🎓 5. Viva Preparation (Q&A)

### Q: "Explain the PRG-to-OWF reduction you implemented."
**A:** "We show that if $G$ is a secure PRG, then $f(s) = G(s)$ must be a OWF. If an adversary could invert $f(s)$ and find the seed $s$, they could easily distinguish our PRG from random bits by simply re-running the generator and checking if the output matches. Since the PRG is secure, such an adversary cannot exist."

### Q: "Why do we need the XOR in the Davies-Meyer OWF?"
**A:** "Without the XOR, $f(k) = AES_k(0)$ is just a permutation. An attacker could potentially use the known '0' input to invert the logic. The XOR effectively 'locks' the function, making it a true One-Way Function."

### Q: "How do you verify the quality of your PRG?"
**A:** "I implemented three NIST SP 800-22 statistical tests: Monobit, Runs, and Serial tests. These calculate p-values based on the distribution of bits. Any p-value above 0.01 indicates that the output passes the statistical randomness threshold."

---

## 📂 6. File Map
- **`crypto/pa01_owf_prg.py`**: The "Heart"—contains the AES-PRG logic and NIST test math.
- **`api/server.py`**: The "Brain"—exposes the `inversion` and `randomness` tasks.
- **`frontend/src/components/PADemoModal.jsx`**: The "Face"—the interactive UI you use for the demo.

---
**Guide Status**: Finalized & Verified.
