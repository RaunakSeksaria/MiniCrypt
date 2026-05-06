# 🎓 Beginner's Guide to the Minicrypt Clique Explorer

Welcome! This project, **Minicrypt Clique Explorer**, is an interactive platform built for the Principles of Information Security course. It visualizes how complex security systems (like Encryption and MPC) are built from simple foundations (like AES or DLP).

---

## 🛠 1. How to Run the Project
Follow these steps to get everything running on your local machine.

### Step A: Setup the Environment (Only once)
We use a virtual environment (`venv`) to keep the project clean.
```bash
# Create the environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install the core dependencies
pip install fastapi uvicorn pydantic
```

### Step B: Start the Backend (API)
This terminal runs the "brain" of the project where all the math happens.
```bash
source venv/bin/activate
python3 -m uvicorn api.server:app --reload
```
*   **Expected Output**: You should see `INFO: Uvicorn running on http://127.0.0.1:8000`.

### Step C: Start the Frontend (UI)
Open a **new terminal** and run the visual interface.
```bash
cd frontend
npm run dev
```
*   **Expected Output**: You should see a link like `http://localhost:5173`. **Click this link to open the app!**

---

## 🧪 2. What to Test & Expected Results

### Scenario 1: Building your first Primitive
1.  Go to the **🔗 Clique Explorer** tab.
2.  Ensure **AES-128 (PRP)** is selected at the top right.
3.  In **Column 1**, select `PRF — Pseudorandom Function`.
4.  Click **Build →**.
    *   **Expected Result**: You should see a step-by-step trace showing how AES-128 is treated as a PRF. A hex value will appear at the bottom.

### Scenario 2: The "Reduction" (Leg 2)
1.  After building a PRF in Scenario 1, go to **Column 2**.
2.  Select `PRP` as the Target Primitive.
3.  Click **Reduce →**.
    *   **Expected Result**: You should see the **Luby-Rackoff 3-round Feistel** reduction. The **Proof Panel** at the bottom will automatically expand to show the security theorem for this reduction.

### Scenario 3: Switching Foundations
1.  Click the **DLP (g^x mod p)** button at the top right.
2.  Go back to **Column 1** and click **Build**.
    *   **Expected Result**: The logic will change! Instead of AES, you will now see modular exponentiation ($g^x \pmod p$) and prime number generation.

### Scenario 4: Interactive Demos (The Fun Part)
1.  Go to the **🧪 PA Demos** tab.
2.  Find **PA#20: 2-Party MPC** and click it.
3.  Type `10` in Alice's box and `5` in Bob's box.
4.  Click **Run Demo**.
    *   **Expected Result**: The app will show you if $10 > 5$ (Comparator) and $10 == 5$ (Equality) using secure logic.
5.  Try **PA#12 (RSA)**: Type a message like "Hello!" and watch it get encrypted and decrypted using RSA-PKCS#1.

---

## 📊 3. Understanding the "Black-Box" Rule
This is the most important part of your assignment. Notice that when you are in **Column 2**, the code **never** directly talks to AES or DLP. It only talks to the "Source" you built in Column 1.
*   **Visual Proof**: Look at the **Dependency Graph** tab. It shows the hierarchy. Every arrow represents a mathematical "reduction" where one primitive is used as a black-box to build the next.

---

## ❓ Troubleshooting
*   **Error "ModuleNotFoundError"**: Make sure you ran `source venv/bin/activate`.
*   **UI shows "Network Error"**: Make sure the Backend terminal (Port 8000) is still running.
*   **Demos not loading**: Ensure you clicked "Run Demo" after changing input values.
