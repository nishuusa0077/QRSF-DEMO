#!/usr/bin/env python3
import os, socket, threading, json, base64, traceback
from pathlib import Path
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = os.environ.get("QRSF_HOST","0.0.0.0")
PORT = int(os.environ.get("QRSF_PORT","6060"))

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s.encode())

def hkdf(shared: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)

PREF_KEMS = ["ML-KEM-512","Kyber512","Classic-McEliece-348864","Classic-McEliece-460896"]
KEMS = oqs.get_enabled_kem_mechanisms()
KEM_NAME = next((k for k in PREF_KEMS if k in KEMS), (KEMS[0] if KEMS else None))
if not KEM_NAME:
    raise RuntimeError("No OQS KEMs available")

print(f"🔐 QRSF Chat Server ({KEM_NAME} + AES-GCM)")

clients_lock = threading.Lock()
# socket -> {"name": str, "s2c": AESGCM}
clients = {}

def send_json(sock, obj):
    sock.sendall(json.dumps(obj).encode() + b"\n")

def recv_json(f):
    line = f.readline()
    if not line:
        return None
    return json.loads(line.decode())

def broadcast(sender: str, plaintext: bytes):
    with clients_lock:
        for s, state in list(clients.items()):
            try:
                nonce = os.urandom(12)
                aad = b"QRSF-chat-s2c"
                ct = state["s2c"].encrypt(nonce, plaintext, aad)
                send_json(s, {"type":"msg","from":sender,"nonce":b64e(nonce),"ciphertext":b64e(ct),"aad":aad.decode()})
            except Exception:
                try: s.close()
                except: pass
                clients.pop(s, None)

def handle_client(conn: socket.socket, addr):
    f = conn.makefile("rwb")
    # Per-connection KEM keypair
    with oqs.KeyEncapsulation(KEM_NAME) as kem:
        pub = kem.generate_keypair()
        send_json(conn, {"type":"kem_pub","alg":KEM_NAME,"pk":b64e(pub)})

        msg = recv_json(f)
        if not msg or msg.get("type")!="kem_ct":
            conn.close(); return
        shared = kem.decap_secret(b64d(msg["ct"]))
        # two independent keys for directions
        k_c2s = hkdf(shared, b"QRSF c2s key")
        k_s2c = hkdf(shared, b"QRSF s2c key")
        aes_c2s = AESGCM(k_c2s)
        aes_s2c = AESGCM(k_s2c)

    # Expect signed-in hello (no PQ signature required in this minimal chat)
    hello = recv_json(f)
    if not hello or hello.get("type")!="hello":
        conn.close(); return
    try:
        n = b64d(hello["nonce"]); c = b64d(hello["ciphertext"]); aad = hello.get("aad","").encode()
        username = aes_c2s.decrypt(n, c, aad).decode(errors="replace")[:32]
    except Exception:
        conn.close(); return

    with clients_lock:
        clients[conn] = {"name": username, "s2c": aes_s2c}

    print(f"👤 {username} joined from {addr[0]}:{addr[1]}")
    broadcast("server", f"👋 {username} joined".encode())

    try:
        while True:
            m = recv_json(f)
            if m is None: break
            if m.get("type")!="data": break
            n = b64d(m["nonce"]); c = b64d(m["ciphertext"]); aad = m.get("aad","").encode()
            pt = aes_c2s.decrypt(n, c, aad)
            meta = m.get("meta",{})
            if meta.get("filename"):
                Path("received").mkdir(exist_ok=True)
                target = Path("received")/meta["filename"]
                i=1
                while target.exists():
                    target = Path("received")/f"{target.stem}_{i}{target.suffix}"
                    i+=1
                with open(target,"wb") as out: out.write(pt)
                print(f"📥 {username} uploaded {target} ({len(pt)} bytes)")
                broadcast("server", f"📁 {username} shared file: {target.name} ({len(pt)} bytes)".encode())
            else:
                text = pt.decode(errors="replace")
                print(f"💬 {username}: {text}")
                broadcast(username, text.encode())
    except Exception as e:
        print(f"⚠️ {username} error: {e}")
        traceback.print_exc()
    finally:
        with clients_lock:
            clients.pop(conn, None)
        try: conn.close()
        except: pass
        print(f"👋 {username} left")
        broadcast("server", f"👋 {username} left".encode())

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(50)
    print(f"📡 Listening on {HOST}:{PORT} (Ctrl+C to stop)")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n🛑 Stopping server.")
    finally:
        s.close()

if __name__ == "__main__":
    main()
