#!/usr/bin/env python3
import os, socket, json, base64
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

HOST = "0.0.0.0"
PORT = int(os.environ.get("QRSF_PORT", "5050"))

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s.encode())

PREF_KEMS = ["ML-KEM-512", "Kyber512",
             "Classic-McEliece-348864", "Classic-McEliece-348864f",
             "Classic-McEliece-460896", "Classic-McEliece-460896f"]
KEMS = oqs.get_enabled_kem_mechanisms()
KEM_NAME = next((k for k in PREF_KEMS if k in KEMS), (KEMS[0] if KEMS else None))
if not KEM_NAME:
    raise RuntimeError("No OQS KEMs available!")

PREF_SIGS = ["ML-DSA-44", "Dilithium2", "Falcon-512", "SPHINCS+-SHA2-128f-simple"]
SIGS = oqs.get_enabled_sig_mechanisms()
SIG_NAME = next((s for s in PREF_SIGS if s in SIGS), None)

def hkdf(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"QRSFv1").derive(shared)

def handle_one_client(conn, kem):
    f = conn.makefile("rwb")

    # 1) Send server KEM public key
    pub = kem.generate_keypair()   # new keypair per client
    f.write(json.dumps({"type":"kem_pub","alg":KEM_NAME,"pk":b64e(pub)}).encode()+b"\n"); f.flush()

    # 2) Receive client's KEM ciphertext -> derive AES key
    msg = json.loads(f.readline().decode())
    if msg.get("type") != "kem_ct":
        return
    ct = b64d(msg["ct"])
    shared = kem.decap_secret(ct)
    key = hkdf(shared)

    # 3) Receive encrypted payload
    msg2 = json.loads(f.readline().decode())
    if msg2.get("type") != "data":
        return
    nonce = b64d(msg2["nonce"])
    ciphertext = b64d(msg2["ciphertext"])
    aad = msg2.get("aad","").encode()

    # Optional signature verification
    if SIG_NAME and msg2.get("sig_alg") and msg2.get("sig_pk") and msg2.get("sig"):
        sig_alg = msg2["sig_alg"]; sig_pk = b64d(msg2["sig_pk"]); sig = b64d(msg2["sig"])
        with oqs.Signature(sig_alg) as vsig:
            vsig.verify(nonce + ciphertext, sig, sig_pk)

    # 4) Decrypt and print/save
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    meta = msg2.get("meta", {})
    if meta.get("filename"):
        with open(meta["filename"], "wb") as out:
            out.write(plaintext)
        print(f"✅ Received file saved to {meta['filename']}")
    else:
        try:
            print("✅ Decrypted message:", plaintext.decode())
        except UnicodeDecodeError:
            print(f"✅ Decrypted binary data ({len(plaintext)} bytes)")

    # 5) Ack
    f.write(json.dumps({"type":"ack","ok":True}).encode()+b"\n"); f.flush()

def main():
    print(f"🔐 QRSF Server starting ({KEM_NAME} + AESGCM)")
    if SIG_NAME:
        print(f"🛡  Signature verification enabled ({SIG_NAME})")
    else:
        print("🛡  No PQ signature mechanism available; authenticity check disabled")

    with oqs.KeyEncapsulation(KEM_NAME) as kem:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        print(f"📡 Listening on {HOST}:{PORT} (Ctrl+C to stop)")
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    handle_one_client(conn, kem)
            except KeyboardInterrupt:
                print("\n🛑 Stopping server.")
                break
            except Exception as e:
                print(f"⚠️  Error handling client: {e}")

if __name__ == "__main__":
    main()
