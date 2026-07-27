# Task 4 Report: Certificate CA + encrypted key storage + leaf cache

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `fe9f6cc` — `feat: self-signed CA generation and MITM leaf cache`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Implemented `internal/certs` with AES-GCM encryption of CA private keys (key derived from `WSP_DATA_KEY` via SHA-256), ECDSA P-256 self-signed CA generation (~10y), on-demand MITM leaf signing (SAN DNS/IP, ~48h), and an in-memory LRU leaf cache (max 1024). Added store methods for the `certificates` table (activate one CA at a time).

---

## Deliverables

| Path | Purpose |
|------|---------|
| `internal/certs/crypto_box.go` | `DeriveKey` / `Seal` / `Open` (AES-256-GCM) |
| `internal/certs/ca.go` | `Provider`, `GenerateSelfSignedCA`, `ActiveCA`, `SignHost` |
| `internal/certs/leaf_cache.go` | Thread-safe LRU leaf cache (max 1024) |
| `internal/certs/ca_test.go` | Unit tests: crypto box, CA → SignHost → chain verify |
| `internal/certs/leaf_cache_test.go` | Unit tests: LRU eviction, expiry, clear |
| `internal/store/certificates.go` | `InsertActiveCertificate`, `GetActiveCertificate`, `GetCertificateByID` |

---

## Certs API

```go
type Provider struct { /* store, dataKey, cache, in-memory CA */ }

func NewProvider(store *store.Store, dataKey string) (*Provider, error)
func (p *Provider) GenerateSelfSignedCA(ctx context.Context, name string) (CertMeta, error)
func (p *Provider) ActiveCA(ctx context.Context) (certPEM []byte, ok bool, err error)
func (p *Provider) SignHost(host string) (*tls.Certificate, error)

func DeriveKey(dataKey string) ([]byte, error) // min 16 chars → SHA-256 → 32 bytes
func Seal(key, plaintext []byte) ([]byte, error)
func Open(key, box []byte) ([]byte, error)

func NewLeafCache(max int) *LeafCache
func (c *LeafCache) Get(host string) (*tls.Certificate, bool)
func (c *LeafCache) Put(host string, cert *tls.Certificate, notAfter time.Time)
func (c *LeafCache) Clear()
```

### Crypto box
- `WSP_DATA_KEY` minimum **16 characters**; rejected if shorter
- Key material: **SHA-256(dataKey)** → 32-byte AES key
- Algorithm: **AES-256-GCM**; storage format `nonce || ciphertext||tag`
- Used only for CA private key PEM at rest (`key_pem_encrypted` BYTEA)

### CA generation
- Algorithm: **ECDSA P-256** (perf preference over RSA 4096)
- Validity: **~10 years** (`DefaultCAValidity`)
- IsCA, path length 0, key usage cert sign / CRL sign / digital signature
- Fingerprint: hex SHA-256 of DER certificate
- On generate: encrypt key, `InsertActiveCertificate` (deactivates prior active CA in a TX), hold key in memory, **clear leaf cache**

### Leaf certificates
- ECDSA P-256 key per host
- Validity: **~48 hours** (`DefaultLeafValidity`)
- SAN: **DNS=host** for hostnames; **IP SAN** when host parses as IP
- Host may include port (`example.com:443` → stripped via `SplitHostPort`)
- `tls.Certificate` includes leaf DER + CA DER for chain presentation
- Cached under normalized host name

### Leaf cache
- LRU max **1024** (`DefaultLeafCacheSize`)
- Entries expire at leaf `NotAfter` minus 5-minute safety margin
- Thread-safe; nil-safe methods

### In-memory CA key
- After `GenerateSelfSignedCA`, CA cert+key stay in process memory for `SignHost`
- If cold process: `SignHost` / `ActiveCA` load active row from store and decrypt key (`loadActiveCA`)
- `store == nil` allowed for unit tests (in-memory only; no persistence)

---

## Store methods added

| Method | Behavior |
|--------|----------|
| `InsertActiveCertificate` | TX: deactivate existing active of same kind → insert active row |
| `GetActiveCertificate` | Active CA by kind; `ok=false` if none |
| `GetCertificateByID` | Full row including encrypted key (server-side) |

Partial unique index `certificates_one_active_ca_idx` remains the DB-level guarantee of a single active self-signed CA.

---

## Verification

| Check | Result |
|-------|--------|
| `go test ./internal/certs/` | PASS |
| `go test ./internal/store/` | PASS |
| `go test ./...` | PASS |
| Live Postgres insert/load of CA | **Not run** — unit tests use `store=nil` in-memory path |

### Unit coverage highlights
- Seal/Open round-trip; wrong key fails; unique nonces
- DeriveKey min length + 32-byte output
- Generate CA → `SignHost("example.com")` → `VerifyHostname` + `x509.Verify` chain to CA
- Leaf ~48h, CA ~10y, ECDSA P-256
- Cache hit reuses serial; CA rotation clears cache and re-signs under new CA
- LRU eviction (max capacity), expired entries, Clear

---

## Self-review

### Matches task brief
- [x] `internal/certs/crypto_box.go`, `ca.go`, `leaf_cache.go`
- [x] Tests: `ca_test.go`, `leaf_cache_test.go`
- [x] AES-GCM box from `WSP_DATA_KEY` (min 16, SHA-256 → 32 bytes)
- [x] ECDSA P-256 CA, PEM cert + encrypted key storage via store
- [x] Leaf LRU max 1024, SAN DNS=host, ~48h validity
- [x] Unit test generate CA → SignHost → verify chain
- [x] Commit `feat: self-signed CA generation and MITM leaf cache`
- [x] Author WSP Dev \<dev@wsp.local\>
- [x] Store methods for `certificates` table
- [x] CA key held in memory after generate/load for `SignHost`
- [x] No Task 5+ (policy, proxy, etc.)

### Concerns / follow-ups
1. **No live DB integration test** for insert/decrypt path — add `//go:build integration` when Postgres is available (mirror auth tests).
2. **`NewProvider` does not pre-load CA** — first `SignHost` after restart decrypts from DB (acceptable; note for cold-start latency).
3. **CA private key never returned from API paths** — only `ActiveCA` public PEM; enforce again in management handlers later.
4. **Leaf clock skew**: notBefore is `now - 5m`; CA uses `now - 1h`.
5. **No HSM / customer subordinate CA** — design allows future `Provider` swap; not in scope.

---

## Out of scope (not done)

- Management `/api/v1/certificates` HTTP handlers / UI
- Wiring `certs.Provider` into `cmd/wsp` or MITM proxy (Task 6+)
- Policy engine (Task 5)
- Customer-uploaded intermediate / subordinate CA
