# Quantum-Resilient Secure Fabric (QRSF)

... # 🔐 Quantum-Resilient Secure Fabric (QRSF)

> **Post-Quantum, Zero-Trust, Future-Proof Secure Communications**

---

## 🌍 Why QRSF?
Today’s encryption (RSA, ECC) **will be broken by quantum computers** in <10 years.  
Big banks, governments, and defense agencies are racing to migrate to **post-quantum cryptography (PQC)**.

**QRSF** is a working prototype of a **quantum-resilient secure communication fabric**, built with:

- **Post-Quantum Key Exchange**: ML-KEM (Kyber), Classic McEliece, BIKE (via [Open Quantum Safe](https://openquantumsafe.org/))  
- **Post-Quantum Digital Signatures**: ML-DSA, Falcon, etc.  
- **Symmetric Encryption**: AES-GCM after PQ handshake  
- **Integrity Layer**: Signatures reject tampered messages  
- **Flexible Negotiation**: Automatically picks strongest PQ algorithm supported by both peers

---

## ⚡ Features
✅ **End-to-End Quantum-Safe Encryption** (client ↔ server, files or messages)  
✅ **Resists MITM & Replay Attacks** (PQC signatures + nonce)  
✅ **File & Chat Mode**: Secure transfer of files or live text chat  
✅ **Drop-in Demo**: Run server + client in minutes  
✅ **DARPA/NSA-ready vision**: A future blueprint for quantum-resilient comms

---

## 🚀 Quick Start

### 1. Clone + Setup
```bash
git clone https://github.com/nishuusa0077/qrsf-demo.git
cd qrsf-demo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
brew install liboqs pkg-config cmake ninja
2. Run Secure Server
bash
Copy
Edit
export QRSF_HOST=127.0.0.1
export QRSF_PORT=6060
export DYLD_FALLBACK_LIBRARY_PATH="$(brew --prefix liboqs)/lib:$DYLD_FALLBACK_LIBRARY_PATH"
./server.py
3. Connect Client
bash
Copy
Edit
./client.py "Quantum-safe hello, world!"
echo "secret plans for quantum era" > plans.txt
./client.py --file plans.txt
✅ Messages/files delivered securely (post-quantum).

📊 Demo Chat Mode
Start a secure group chat (PQ handshake + AES session):

bash
Copy
Edit
./server_chat.py
./client_chat.py Alice
./client_chat.py Bob
Encrypted PQ messages flow seamlessly in real time.

🛡 Why It Matters
RSA/ECC → broken in quantum era

PQC (NIST standardization) → the next frontier

QRSF shows how to practically integrate PQC into real systems today

A launchpad for banks, defense, healthcare, cloud providers to explore migration

📌 Roadmap
🌐 Multi-node mesh networking

🔑 Hybrid mode (classical + PQ dual-encryption)

🖥 GUI for non-technical users

☁️ Secure cloud deployment module

📡 IoT/5G/Drone secure comms extension

👨‍💻 Author
Built by Nishant Chaudhary
🎓 M.Eng. Engineering Management, Stevens Institute of Technology
💡 Focus: Cybersecurity, Post-Quantum Cryptography, Systems Design

⚠️ Disclaimer
This is a research demo — not production-grade yet.
Use QRSF to learn, test, and spark innovation in the quantum-security era. ...
