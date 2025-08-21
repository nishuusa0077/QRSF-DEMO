import os, time, statistics, socket, json, base64, argparse, secrets, pathlib, hashlib
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64e=lambda b: base64.b64encode(b).decode()
b64d=lambda s: base64.b64decode(s.encode())

HOST = os.environ.get("HOST","127.0.0.1")
PORT = int(os.environ.get("QRSF_PORT","6060"))

def pick_kem():
    prefs = ["ML-KEM-512","Kyber512","Classic-McEliece-348864","Classic-McEliece-348864f",
             "Classic-McEliece-460896","Classic-McEliece-460896f"]
    kems = oqs.get_enabled_kem_mechanisms()
    for k in prefs:
        if k in kems: return k
    if not kems: raise RuntimeError("No OQS KEMs available")
    return kems[0]

def pick_sig():
    prefs = ["ML-DSA-44","Dilithium2","Falcon-512","SPHINCS+-SHA2-128f-simple"]
    sigs = oqs.get_enabled_sig_mechanisms()
    for s in prefs:
        if s in sigs: return s
    return None

def send_one(payload: bytes, kem_hint=None, require_sig=False):
    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb")
    g = json.loads(f.readline().decode())
    alg, pk = g["alg"], b64d(g["pk"])
    kem_name = alg if kem_hint is None else kem_hint
    with oqs.KeyEncapsulation(kem_name) as kem:
        t0 = time.perf_counter()
        ct, shared = kem.encap_secret(pk)
        f.write(json.dumps({"type":"kem_ct","ct":b64e(ct)}).encode()+b"\n"); f.flush()
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"QRSFv1").derive(shared)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        aad = b"QRSF-demo"
        ctxt = aesgcm.encrypt(nonce, payload, aad)
        out = {
            "type":"data",
            "nonce":b64e(nonce),
            "ciphertext":b64e(ctxt),
            "aad":aad.decode(),
            "meta":{}
        }
        # signature (server likely requires if available)
        sig_alg = None
        if require_sig:
            sig_alg = pick_sig()
            if not sig_alg:
                s.close(); raise RuntimeError("Signature required but none available")
        else:
            sig_alg = pick_sig()
        if sig_alg:
            with oqs.Signature(sig_alg) as sig:
                pk_sig = sig.generate_keypair()
                signature = sig.sign(nonce + ctxt)
                out.update({"sig_alg":sig_alg,"sig_pk":b64e(pk_sig),"sig":b64e(signature)})

        f.write(json.dumps(out).encode()+b"\n"); f.flush()
        # ack (server sends JSON line)
        _ = f.readline()
        dt = time.perf_counter() - t0
    s.close()
    return dt, alg, sig_alg

def human(n):
    return f"{n:.3f}"

def write_report(lat_samples, kem_used, sig_used, file_time, file_bytes):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    p50 = statistics.median(lat_samples) if lat_samples else 0
    p90 = statistics.quantiles(lat_samples, n=10)[8] if len(lat_samples)>=10 else max(lat_samples) if lat_samples else 0
    p99 = statistics.quantiles(lat_samples, n=100)[98] if len(lat_samples)>=100 else max(lat_samples) if lat_samples else 0
    avg = statistics.mean(lat_samples) if lat_samples else 0
    mn  = min(lat_samples) if lat_samples else 0
    mx  = max(lat_samples) if lat_samples else 0

    recv_dir = pathlib.Path("received")
    files_md = []
    if recv_dir.exists():
        for f in sorted(recv_dir.glob("*")):
            h = hashlib.sha256(f.read_bytes()).hexdigest()
            files_md.append(f"- {f.name}  \n  SHA256: `{h}`  \n  Size: {f.stat().st_size} bytes")

    report = []
    report.append("# QRSF Benchmark Addendum\n")
    report.append(f"Generated: **{now}**")
    report.append("\n## Config\n")
    report.append(f"- Host/Port: `{HOST}:{PORT}`")
    report.append(f"- KEM (server announced): `{kem_used}`")
    report.append(f"- Signatures: `{sig_used or 'none'}` (client-side)\n")
    report.append("## Message Latency (includes per-message KEM + AES-GCM)\n")
    report.append(f"- Samples: {len(lat_samples)}")
    report.append(f"- p50: {human(p50)} s")
    report.append(f"- p90: {human(p90)} s")
    report.append(f"- p99: {human(p99)} s")
    report.append(f"- avg: {human(avg)} s  (min: {human(mn)} s, max: {human(mx)} s)\n")
    if file_bytes and file_time:
        mbps = (file_bytes*8/1e6)/file_time
        report.append("## File Throughput\n")
        report.append(f"- File size: {file_bytes} bytes")
        report.append(f"- Transfer time (1 msg): {human(file_time)} s")
        report.append(f"- Approx throughput: {human(mbps)} Mbit/s\n")
    report.append("## Received Files (server side)\n")
    report.append("\n".join(files_md or ["- (none found)"]))
    report.append("\n---\n")
    # Append to (or create) main report
    path = pathlib.Path("QRSF_demo_report.md")
    base = path.read_text() if path.exists() else "# Quantum-Resilient Security Fabric (QRSF) Demo Report\n"
    path.write_text(base + "\n\n" + "\n".join(report) + "\n")
    print(f"✅ Bench results appended to {path}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--messages", type=int, default=100, help="number of small messages")
    ap.add_argument("--payload-size", type=int, default=64, help="payload bytes per message")
    ap.add_argument("--file-size-mb", type=int, default=5, help="size of single file transfer (MB)")
    ap.add_argument("--require-sig", action="store_true", help="require PQ signature on client side")
    args = ap.parse_args()

    payload = secrets.token_bytes(args.payload_size)
    samples = []
    kem_used = None
    sig_used = None

    for i in range(args.messages):
        dt, kem, sig = send_one(payload, require_sig=args.require_sig)
        kem_used = kem_used or kem
        sig_used = sig_used or sig
        samples.append(dt)
        if (i+1) % 10 == 0:
            print(f"[{i+1}/{args.messages}] {dt:.3f}s")

    # file test
    file_bytes = args.file_size_mb * 1024 * 1024
    big = secrets.token_bytes(file_bytes)
    fdt, kem2, sig2 = send_one(big, require_sig=args.require_sig)
    kem_used = kem_used or kem2
    sig_used = sig_used or sig2

    write_report(samples, kem_used, sig_used, fdt, file_bytes)

if __name__ == "__main__":
    main()
