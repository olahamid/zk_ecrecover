# 🔐 zk_ecrecover

A Noir circuit that verifies ECDSA signatures **while preventing signature malleability**.  
It ensures a signature is valid **only if** `s ≤ curve_order / 2` (canonical form) to prevent `(r, n - s)` replay exploits.

Without this, an attacker could replace a valid signature (r, s) with (r, n - s) and still pass verification.

✅ Features:

- Splits and checks the s value in array form

- Reconstructs the full signature for proper recovery

- Asserts the recovered address matches the expected one



[![MIT License](https://img.shields.io/github/license/olahamid/ZKEcrecover.svg?style=for-the-badge)](https://github.com/olahamid/ZKEcrecover/blob/main/LICENSE)

---

## 🛠️ Built With

- [Noir](https://noir-lang.org/)
- Nargo (Noir's CLI tool)
- secp256k1 signature verification
- Ecrecover syscall

---

## ⚙️ How to Run

```bash
# Clone the repo
git clone https://github.com/olahamid/ZKEcrecover.git
cd zk_ecrecover

# Compile the circuit
nargo compile

# Run the logic with example inputs
nargo execute

# Prove and verify (optional)
nargo prove
nargo verify
