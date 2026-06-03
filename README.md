# pqctl

> OpenSSL for the post-quantum era.

`pqctl` is a developer-friendly CLI for post-quantum cryptography. Single static binary. Uses NIST-standardized algorithms. Free forever.

OpenSSL has no PQC support and a painful UX. `pqctl` fixes both.

---

## Algorithms

| Algorithm | Type | Standard |
|-----------|------|----------|
| ML-DSA-65 | Signing | FIPS 204 |
| ML-KEM-768 | Key encapsulation | FIPS 203 |
| Ed25519 | Signing (classical) | RFC 8032 |
| Hybrid | ML-DSA-65 + Ed25519 | — |

---

## Install

```bash
go install github.com/rjcuff/pqctl@latest
```

Or build from source:

```bash
git clone https://github.com/rjcuff/pqctl
cd pqctl
go build -o pqctl .
```

---

## Usage

### Key generation

```bash
# ML-DSA-65 (default, NIST-recommended post-quantum signing)
pqctl keygen --out mykey
# → mykey.priv.pem + mykey.pub.pem

# ML-KEM-768 (post-quantum encryption)
pqctl keygen --algo ml-kem-768 --out mykey

# Ed25519 (classical)
pqctl keygen --algo ed25519 --out mykey

# Hybrid (ML-DSA-65 + Ed25519)
pqctl keygen --algo hybrid --out mykey
```

### Signing

```bash
pqctl sign --key mykey.priv.pem --in file.txt
pqctl verify --pubkey mykey.pub.pem --in file.txt --sig file.txt.sig
```

### Encryption

```bash
# generate a KEM keypair first
pqctl keygen --algo ml-kem-768 --out kemkey

pqctl encrypt --recipient kemkey.pub.pem --in secret.txt
pqctl decrypt --key kemkey.priv.pem --in secret.txt.enc --out secret.txt
```

### Inspect

```bash
pqctl inspect mykey.pub.pem
# file:      mykey.pub.pem
# type:      ML-DSA-65 PUBLIC KEY
# algorithm: ML-DSA-65 (FIPS 204 — post-quantum signing)
# key type:  public
# size:      1952 bytes
```

---

## Why post-quantum?

Classical algorithms (RSA, ECDSA, X25519) are broken by sufficiently large quantum computers running Shor's algorithm. NIST finalized ML-DSA and ML-KEM in 2024 as the replacement standards. `pqctl` makes them as easy to use as `openssl genrsa`.

**Harvest now, decrypt later:** attackers are already recording encrypted traffic today. When quantum computers arrive, they decrypt it retroactively. The time to migrate is now.

---

## Project structure

```
pqctl/
├── main.go          # entry point
├── cmd/             # CLI commands (cobra)
├── crypto/          # pure crypto logic (no CLI deps)
└── keys/            # PEM serialization
```

`cmd/` knows about CLI. `crypto/` knows nothing but bytes and errors. Clean separation means `crypto/` is fully testable without touching the filesystem.

---

## Built with

- [Cloudflare CIRCL](https://github.com/cloudflare/circl) — Go PQC library
- [Cobra](https://github.com/spf13/cobra) — CLI framework
- Go 1.22+

---

## Status & Caveats

**Alpha.** Do not use to protect production secrets yet.

**PEM format note:** ML-DSA and ML-KEM PEM/PKIX encodings are not yet RFC-standardized (as of mid-2026). pqctl's PEM format is internally consistent — keys round-trip correctly — but will not interoperate with OpenSSL or other tools until IETF LAMPS drafts finalize.

---

## License

MIT
