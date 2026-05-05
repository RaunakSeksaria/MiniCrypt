# POIS Cryptographic Stack & Minicrypt Explorer

Welcome to the **Principles of Information Security (CS8.401)** Cryptographic Stack project. 

This repository contains a complete, from-scratch implementation of the "Minicrypt Clique" reduction chain. Over the course of 20 programming assignments (PA#1 to PA#20), we have implemented foundational cryptographic primitives, symmetric cryptography, hashing, public-key cryptography, and secure multi-party computation.

**Absolutely no external cryptographic libraries were used.** Everything from AES to Miller-Rabin primality testing, RSA, ElGamal, Oblivious Transfer, and Yao/GMW boolean circuits was built in pure Python using only standard math and `os.urandom`.

## Phase 6: The Web Explorer (PA#0)
This repository includes a beautiful, interactive web application (powered by FastAPI and Vanilla JS/CSS) to visualize the entire Minicrypt Equivalence Theorem. 

The web explorer allows you to:
1. **Build & Reduce:** Start with a foundation (AES or DLP), build a source primitive, and reduce it to a target primitive (e.g. `AES → PRG → PRF`).
2. **View Proofs:** See the exact cryptographic theorems (e.g., HILL, GGM, Luby-Rackoff) mapped to each reduction.
3. **Interactive Demos:** Run live simulations of all 20 programming assignments (e.g. demonstrating a malleability attack on raw RSA, or executing a Secure AND gate via Oblivious Transfer) directly in your browser.
4. **Dependency Graph:** A live SVG map showing how all 20 modules depend on each other.

---

## 🚀 How to Run the Web Application

### Prerequisites
Make sure you have Python 3.8+ installed.

### 1. Install Dependencies
The core cryptography requires no dependencies. Only the Web Explorer backend requires a few lightweight libraries.
```bash
pip install fastapi uvicorn
```

### 2. Start the Server
Navigate to the root directory of this project and run the FastAPI server:
```bash
python3 -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Open the Explorer
Open your web browser and go to:
[http://localhost:8000](http://localhost:8000)

---

## 💻 How to Run CLI Demos

Every single cryptographic module can also be run independently from the command line to view its internal mathematical operations and security game simulations.

Simply execute any module from the root directory. For example:

**Run the Birthday Attack Simulation (PA#9):**
```bash
python3 -m crypto.pa09_birthday
```

**Run the Oblivious Transfer Protocol (PA#18):**
```bash
python3 -m crypto.pa18_ot
```

**Run the 2-Party MPC Circuits (PA#20):**
```bash
python3 -m crypto.pa20_mpc
```

---

## Project Structure
- `crypto/` — Contains all 20 pure-Python cryptographic implementations (PA#1–20).
- `api/server.py` — The FastAPI backend routing table mapping web requests to the python crypto code.
- `web/` — The frontend HTML, CSS, and JS for the beautiful dark-mode explorer.
- `pois_project_full.txt` — The original assignment specification.

---

## License
Created for CS8.401 Principles of Information Security. All rights reserved.
