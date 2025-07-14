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

Ran 1 test for test/Counter.t.sol:CounterTest
[PASS] testSepertePubAddrXandY() (gas: 10851)
Logs:
  X: 71846145234831510624997290141421328468896781196316289340617638880016358871367
  Y: 96897368154696653878464222873507205893620449049996228453752597643913676402252
  Addr: 0x7d49C2e4da3Cf0B04e7B31cE33791996Ab8532Ce
  Private Key: 0x512fa78a30796bc8f51c67806d6e498a6087b257c00fe2d6b9c9f162b1745dab

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.08ms (1.24ms CPU time)

### test for sepreration:
```solidity
    function testSepertePubAddrXandY() public {
        Vm.Wallet memory wallet = vm.createWallet("ola-wallet");
        emit log_named_uint("X", wallet.publicKeyX);
        emit log_named_uint("Y", wallet.publicKeyY);
        emit log_named_address("Addr", wallet.addr);
        emit log_named_bytes32("Private Key (hex)", bytes32(wallet.privateKey));
    }
```