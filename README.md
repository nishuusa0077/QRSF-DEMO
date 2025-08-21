# Quantum-Resilient Secure Fabric (QRSF)

# 🔐 Quantum-Resilient Secure Fabric (QRSF)

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

