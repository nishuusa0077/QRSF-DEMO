#!/usr/bin/env python3
import os, sys, socket, json, base64, pathlib
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = os.environ.get("QRSF_HOST","127.0.0.1")
PORT = int(os.environ.get("QRSF_PORT","6060"))

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s.encode())

def hkdf(shared: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)

def main():
    if len(sys.argv) < 2:
        print("Usage: ./client_chat.py <YourName>")
        sys.exit(1)
    name = sys.argv[1]

    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb")

    g = json.loads(f.readline().decode())
    if g.get("type")!="kem_pub": raise RuntimeError("Bad server greeting")
    alg, pk = g["alg"], b64d(g["pk"])

    with oqs.KeyEncapsulation(alg) as kem:
        ct, shared = kem.encap_secret(pk)
        f.write(json.dumps({"type":"kem_ct","ct":b64e(ct)}).encode()+b"\n"); f.flush()

    k_c2s = hkdf(shared, b"QRSF c2s key")
    k_s2c = hkdf(shared, b"QRSF s2c key")
    aes_c2s = AESGCM(k_c2s)
    aes_s2c = AESGCM(k_s2c)

    # send hello (username)
    n = os.urandom(12); aad = b"QRSF-hello"
    c = aes_c2s.encrypt(n, name.encode(), aad)
    f.write(json.dumps({"type":"hello","nonce":b64e(n),"ciphertext":b64e(c),"aad":aad.decode()}).encode()+b"\n"); f.flush()

    print("✅ Connected. Type messages and press Enter.")
    print("   Commands: /sendfile <path>   /quit")

    # background receiver
    import threading
    def rx():
        while True:
            line = f.readline()
            if not line:
                print("🔌 Disconnected.")
                os._exit(0)
            m = json.loads(line.decode())
            if m.get("type")=="msg":
                n = b64d(m["nonce"]); c = b64d(m["ciphertext"]); aad = m.get("aad","").encode()
                try:
                    pt = aes_s2c.decrypt(n, c, aad)
                    who = m.get("from","server")
                    try:
                        text = pt.decode()
                        print(f"\r💬 {who}: {text}\n> ", end="", flush=True)
                    except UnicodeDecodeError:
                        print(f"\r💬 {who}: [binary {len(pt)} bytes]\n> ", end="", flush=True)
                except Exception as e:
                    print("\n⚠️ Decrypt error:", e)
    threading.Thread(target=rx, daemon=True).start()

    try:
        while True:
            msg = input("> ").strip()
            if not msg: continue
            if msg.lower() in ("/quit","/exit"): break
            if msg.startswith("/sendfile "):
                p = pathlib.Path(msg.split(" ",1)[1]).expanduser()
                if not p.exists() or not p.is_file():
                    print("❌ File not found"); continue
                data = p.read_bytes()
                aad = b"QRSF-chat-c2s"
                n = os.urandom(12)
                c = aes_c2s.encrypt(n, data, aad)
                out = {"type":"data","nonce":b64e(n),"ciphertext":b64e(c),"aad":aad.decode(),"meta":{"filename":p.name}}
                f.write(json.dumps(out).encode()+b"\n"); f.flush()
                print(f"📤 sent file {p.name} ({len(data)} bytes)")
                continue

            data = msg.encode()
            aad = b"QRSF-chat-c2s"
            n = os.urandom(12)
            c = aes_c2s.encrypt(n, data, aad)
            out = {"type":"data","nonce":b64e(n),"ciphertext":b64e(c),"aad":aad.decode(),"meta":{}}
            f.write(json.dumps(out).encode()+b"\n"); f.flush()
    finally:
        s.close()

if __name__ == "__main__":
    main()
