# 🛡️ PA#2 Master Guide: Pseudorandom Functions (GGM)

This guide contains the essential theoretical and practical knowledge needed to defend your **PA#2** implementation during the viva.

---

## 🏗️ 1. The Core Construction: GGM Tree
**Q: What is the GGM Construction?**
**A:** The GGM (Goldreich-Goldwasser-Micali) construction is a method to build a **Pseudorandom Function (PRF)** from any **Length-Doubling PRG**.

**Q: How does the tree-walking work?**
**A:** 
1. The input $x$ is treated as a sequence of bits $(b_1, b_2, \dots, b_n)$.
2. We start at the **Root** with the secret key $k$ (the initial seed).
3. For each bit $b_i$:
   - If $b_i = 0$, we move to the **Left Child** by computing $G_0(current\_seed)$.
   - If $b_i = 1$, we move to the **Right Child** by computing $G_1(current\_seed)$.
4. After $n$ steps, the value at the leaf is the PRF output $F_k(x)$.

---

## 🔬 2. Security & The Distinguishing Game
**Q: What makes a function a "PRF"?**
**A:** A function is a PRF if no polynomial-time adversary can distinguish between:
1. A **Real PRF** $F_k$ (where $k$ is random).
2. A **Truly Random Function** $R$ (which returns a random string for every unique input).

**Q: How do you prove it in your project?**
**A:** We implement a **Distinguishing Game**. We make 100 queries to both a PRF and a Random Function. We show that the statistical properties (like the 0/1 bit ratio) are nearly identical, proving they are computationally indistinguishable.

---

## 🔄 3. Bidirectional Reductions
**Q: Can you go backward? (PRF → PRG)**
**A:** Yes! If you have a PRF, you can easily build a PRG.
- **Construction**: $G(s) = F_s(0) \parallel F_s(1)$
- This takes an $n$-bit seed and produces $2n$ bits of output, satisfying the length-doubling requirement of a PRG.

---

## 🛠️ 4. Technical Implementation (CLI & API)
- **File**: `crypto/pa02_prf_ggm.py`
- **Key Class**: `GGM_PRF`
- **Method**: `evaluate(key, x)`
- **Optimization**: For production, we use the **AES-PRF Plug-in** ($F_k(x) = AES_k(x)$) because it is hardware-accelerated, but the GGM Tree is used for the theoretical proof.

---

## 🎯 5. Viva "A-Grade" Answers
**Q: Why not just use AES as a PRF directly?**
**A:** "In practice, we do. However, PA#2 is about **Minicrypt Theory**. We prove that we only *need* a One-Way Function to build a PRF. By building a PRG from an OWF (PA#1) and then a PRF from that PRG (PA#2), we demonstrate that the existence of OWFs is sufficient for symmetric cryptography."

**Q: What is the depth of your GGM tree?**
**A:** "For our 128-bit AES foundation, the tree has a depth of **128**. This means every PRF evaluation involves 128 calls to the underlying PRG."
