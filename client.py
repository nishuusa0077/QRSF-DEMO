#!/usr/bin/env python3
import os, sys, socket, json, base64, pathlib
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

HOST = "127.0.0.1"
PORT = int(os.environ.get("QRSF_PORT", "5050"))

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s.encode())

# --- Pick KEM; will adapt to what server announces ---
PREF_KEMS = ["ML-KEM-512", "Kyber512",
             "Classic-McEliece-348864", "Classic-McEliece-348864f",
             "Classic-McEliece-460896", "Classic-McEliece-460896f"]
KEMS = oqs.get_enabled_kem_mechanisms()
KEM_NAME = next((k for k in PREF_KEMS if k in KEMS), (KEMS[0] if KEMS else None))
if not KEM_NAME:
    raise RuntimeError("No OQS KEMs available!")

# --- Optional signatures (auto-skip if none available) ---
PREF_SIGS = ["ML-DSA-44", "Dilithium2", "Falcon-512", "SPHINCS+-SHA2-128f-simple"]
SIGS = oqs.get_enabled_sig_mechanisms()
SIG_NAME = next((s for s in PREF_SIGS if s in SIGS), None)

def hkdf(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"QRSFv1").derive(shared)

def main():
    # Choose data: message (default) or --file path
    data = b"Hello from a quantum-safe client!"
    meta = {}
    if len(sys.argv) > 1:
        if sys.argv[1] == "--file" and len(sys.argv) >= 3:
            p = pathlib.Path(sys.argv[2])
            data = p.read_bytes()
            meta["filename"] = p.name
        else:
            data = " ".join(sys.argv[1:]).encode()

    sock = socket.create_connection((HOST, PORT))
    with sock, oqs.KeyEncapsulation(KEM_NAME) as kem:
        f = sock.makefile("rwb")

        # Receive server public key + alg
        srv = json.loads(f.readline().decode())
        assert srv.get("type") == "kem_pub", "Bad server greeting"
        srv_alg = srv.get("alg")
        pk = b64d(srv["pk"])

        # Match the server's KEM if different
        kem_name = srv_alg if srv_alg in KEMS else KEM_NAME
        if kem_name != KEM_NAME:
            kem = oqs.KeyEncapsulation(kem_name)

        # Encapsulate -> send ct
        ct, shared = kem.encap_secret(pk)
        f.write(json.dumps({"type":"kem_ct","ct":b64e(ct)}).encode()+b"\n"); f.flush()

        # Derive AES key, encrypt payload
        key = hkdf(shared)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        aad = b"QRSF-demo"
        ciphertext = aesgcm.encrypt(nonce, data, aad)

        out = {
            "type":"data",
            "nonce":b64e(nonce),
            "ciphertext":b64e(ciphertext),
            "aad":aad.decode(),
            "meta":meta
        }

        # Optional signature (sign nonce||ciphertext)
        if SIG_NAME:
            with oqs.Signature(SIG_NAME) as sig:
                sig_pk = sig.generate_keypair()
                signature = sig.sign(nonce + ciphertext)
                out.update({
                    "sig_alg": SIG_NAME,
                    "sig_pk": b64e(sig_pk),
                    "sig": b64e(signature)
                })

        f.write(json.dumps(out).encode()+b"\n"); f.flush()

        ack = json.loads(f.readline().decode())
        print("✅ Delivered securely (post-quantum)." if ack.get("ok") else "⚠️ No ack")

    print("🏁 Client done.")
if __name__ == "__main__":
    main()
