# 🔐 Password Strength Analyzer & Cryptographic Reuse Guard

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Cryptography](https://img.shields.io/badge/Crypto-PBKDF2--HMAC--SHA256-orange.svg)
![Dependencies](https://img.shields.io/badge/Core_Dependencies-Zero-brightgreen.svg)

A comprehensive cybersecurity tool that evaluates the strength of user-entered passwords using **information theory (Shannon & Pool Entropy)**, detects structural and dictionary vulnerabilities, suggests cryptographically strong alternatives via OS-level CSPRNG (`secrets`), and integrates with a **SQLite database using salted PBKDF2-HMAC-SHA256 hashing** to prevent the reuse of historical passwords.

---

## ✨ Key Features

1. **Multi-Dimensional Strength Evaluation (`src/analyzer.py`)**
   - **Length & Character Complexity:** Checks lowercase, uppercase, numeric digits, and special symbols against NIST SP 800-63B guidelines.
   - **Uniqueness & Repetition Analysis:** Computes character uniqueness ratios and flags consecutive character runs (e.g., `aaa`, `111`).
   - **Dual Entropy Calculation:** Computes both **Pool Entropy** ($E = L \times \log_2(R)$) and **Shannon Information Entropy** ($H = -\sum p_i \log_2 p_i$).
   - **Heuristic Pattern Detection:** Detects keyboard walks (`qwerty`, `asdf`), alphabetical/numeric sequences (`123`, `abc`), calendar years (`1999`, `2026`), and top breached passwords.
   - **Offline Crack-Time Estimation:** Estimates brute-force resistance against a modern 10-Billion guesses/sec GPU cluster.

2. **Cryptographically Secure Password Suggester (`src/generator.py`)**
   - Uses Python's `secrets` module (Cryptographically Secure Pseudo-Random Number Generator) instead of predictable `random`.
   - Generates three distinct recommendation types:
     1. **Input-Strengthened Variant:** Mutates and salts the user's weak password into a high-entropy version.
     2. **Diceware-Style Memorable Passphrase:** Multi-word capitalized passphrase with symbols and digits.
     3. **Maximum-Security Random Key:** 18-character uniform CSPRNG string guaranteed to include all 4 character classes.

3. **Salted Database Integration for Reuse Prevention (`src/database.py`)**
   - Stores historical passwords in SQLite using **PBKDF2-HMAC-SHA256** with **200,000 iterations** and a unique **16-byte (128-bit) cryptographic salt** per entry.
   - **Zero Plaintext Storage:** Plaintext passwords are never written to disk.
   - **Timing-Attack Resistance:** Verifies candidate passwords against historical hashes using constant-time comparison (`hmac.compare_digest`).

---

## 📂 Repository Structure

```text
password-strength-analyzer/
├── README.md                  # Project documentation & cryptographic breakdown
├── LICENSE                    # MIT License
├── .gitignore                 # Excludes local SQLite DBs and Python cache
├── requirements.txt           # Optional web/testing packages
├── main.py                    # Interactive CLI & command-line interface
├── app.py                     # Optional Flask Web UI dashboard
├── src/
│   ├── __init__.py
│   ├── analyzer.py            # Entropy, pattern & complexity analysis engine
│   ├── generator.py           # CSPRNG password & passphrase generator
│   └── database.py            # SQLite + PBKDF2-HMAC-SHA256 password history guard
└── tests/
    └── test_analyzer.py       # Automated unit tests
```

---

## 🚀 Quick Start & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/password-strength-analyzer.git
cd password-strength-analyzer
```

### 2. Run Interactive CLI Mode (No External Packages Needed)
```bash
python main.py
```

### 3. Single-Command CLI Evaluation & Database Check
```bash
# Evaluate a single password
python main.py --password "password123"

# Evaluate and store password for a user in SQLite history DB
python main.py --user "alice" --password "Vanguard-Solar-Crystal-842!"
```

### 4. Launch the Web UI Dashboard (Optional)
```bash
pip install -r requirements.txt
python app.py
```
Then open **`http://127.0.0.1:5000`** in your browser.

---

## 🧪 Running Unit Tests

Verify all cryptographic, analytical, and database modules using `unittest`:
```bash
python -m unittest discover -s tests -v
```

---

## 🧠 Cryptographic Concepts Covered

| Concept | Mathematical / Technical Implementation | Why It Matters |
| :--- | :--- | :--- |
| **Pool Entropy** | $E = L \times \log_2(R)$ | Quantifies the keyspace size based on length ($L$) and character pool ($R \in [26, 94]$). |
| **Shannon Entropy** | $H(X) = -L \sum P(x_i) \log_2 P(x_i)$ | Penalizes strings with repeated characters (e.g., `aaaaaaaaaa` has 0 bits of Shannon entropy). |
| **CSPRNG (`secrets`)** | OS-seeded `/dev/urandom` or `CryptGenRandom` | Prevents attackers from predicting generated passwords by observing PRNG state. |
| **Salted Key Stretching** | `PBKDF2-HMAC-SHA256` (16B salt + 200k rounds) | Defeats Rainbow Table precomputation and slows down GPU brute-force attacks by $200,000\times$. |
| **Constant-Time Verification** | `hmac.compare_digest(a, b)` | Prevents side-channel timing attacks during hash comparison. |

---

## 📜 License
Released under the [MIT License](LICENSE).
