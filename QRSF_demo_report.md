# Quantum-Resilient Security Fabric (QRSF) Demo Report


Generated: **2025-08-21 17:17:39**


## Environment


- Python: 3.11.2


- Platform: Darwin 24.5.0


## Available Post-Quantum Algorithms


- KEMs: ['BIKE-L1', 'BIKE-L3', 'BIKE-L5', 'Classic-McEliece-348864', 'Classic-McEliece-348864f', 'Classic-McEliece-460896', 'Classic-McEliece-460896f', 'Classic-McEliece-6688128', 'Classic-McEliece-6688128f', 'Classic-McEliece-6960119'] ...


- Signatures: ['Dilithium2', 'Dilithium3', 'Dilithium5', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'Falcon-512', 'Falcon-1024', 'Falcon-padded-512', 'Falcon-padded-1024'] ...


## Received Files
- (none found)

# QRSF Benchmark Addendum

Generated: **2025-08-21 17:19:11**

## Config

- Host/Port: `127.0.0.1:6060`
- KEM (server announced): `ML-KEM-512`
- Signatures: `ML-DSA-44` (client-side)

## Message Latency (includes per-message KEM + AES-GCM)

- Samples: 200
- p50: 0.000 s
- p90: 0.001 s
- p99: 0.005 s
- avg: 0.001 s  (min: 0.000 s, max: 0.019 s)

## File Throughput

- File size: 10485760 bytes
- Transfer time (1 msg): 0.254 s
- Approx throughput: 330.673 Mbit/s

## Received Files (server side)

- (none found)

---

