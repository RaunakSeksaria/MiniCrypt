# MiniCrypt

A from-scratch implementation of the Minicrypt reduction chain: foundational cryptographic primitives, symmetric cryptography, hashing, public-key cryptography, and secure multi-party computation — with an interactive web explorer for visualizing how each primitive reduces to the next.

No external cryptographic libraries are used. AES, Miller–Rabin primality testing, RSA, ElGamal, Diffie–Hellman, Oblivious Transfer, and Yao/GMW boolean circuits are all implemented in pure Python on top of standard integer arithmetic and `os.urandom`.

## The Web Explorer

A FastAPI backend and React frontend that visualize the Minicrypt equivalence theorem:

1. **Build & Reduce:** Start with a foundation (AES or DLP), build a source primitive, and reduce it to a target primitive (e.g. `AES → PRG → PRF`).
2. **View Proofs:** See the cryptographic theorems (HILL, GGM, Luby-Rackoff) mapped to each reduction step.
3. **Interactive Demos:** Run live simulations in the browser — birthday attacks on toy hashes, malleability attacks on raw RSA, IND-CPA security games, a Secure AND gate over Oblivious Transfer, and more.
4. **Dependency Graph:** A live SVG map showing how the modules build on each other.

## Running the Explorer

Requires Python 3.8+ and Node.js.

Install the backend dependencies (the cryptography itself needs none):

```bash
pip install fastapi uvicorn
```

Start the API server from the repository root:

```bash
python3 -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
```

Start the frontend dev server:

```bash
cd frontend && npm install && npm run dev
```

Then open [http://localhost:5173](http://localhost:5173).

## Running Modules from the CLI

Every cryptographic module runs independently from the command line, printing its internal operations and security-game simulations.

```bash
# Birthday attack simulation
python3 -m crypto.birthday

# 1-of-2 Oblivious Transfer protocol
python3 -m crypto.ot

# Two-party MPC circuit evaluation
python3 -m crypto.mpc
```

## Project Structure

- `crypto/` — the pure-Python cryptographic implementations, one module per primitive or protocol.
- `api/server.py` — the FastAPI backend exposing the crypto modules and the reduction engine over REST.
- `frontend/` — the React + Vite explorer UI.
