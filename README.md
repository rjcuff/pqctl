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
# ML-DSA-65 (default, NIST-recommended)
pqctl keygen --out mykey
# → mykey.priv.pem + mykey.pub.pem

# Ed25519 (classical)
pqctl keygen --algo ed25519 --out mykey

# Hybrid (ML-DSA-65 + Ed25519)
pqctl keygen --algo hybrid --out mykey
```

### Signing _(coming in Phase 2)_

```bash
pqctl sign file.txt --key mykey.priv.pem --out file.txt.sig
pqctl verify file.txt --sig file.txt.sig --pubkey mykey.pub.pem
```

### Encryption _(coming in Phase 4)_

```bash
pqctl encrypt file.txt --recipient mykey.pub.pem --out file.txt.enc
pqctl decrypt file.txt.enc --key mykey.priv.pem --out file.txt
```

---

## Why post-quantum?

Classical algorithms (RSA, ECDSA, X25519) are broken by sufficiently large quantum computers running Shor's algorithm. NIST finalized ML-DSA and ML-KEM in 2024 as the replacement standards. `pqctl` makes them as easy to use as `openssl genrsa`.

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

## Roadmap

- [x] Phase 1 — `keygen` (ML-DSA-65, Ed25519, hybrid)
- [ ] Phase 2 — `sign` + `verify`
- [ ] Phase 3 — `inspect` + file format polish
- [ ] Phase 4 — `encrypt` + `decrypt` (ML-KEM-768)
- [ ] Phase 5 — v0.1.0 release + binary downloads

---

## License

MIT
