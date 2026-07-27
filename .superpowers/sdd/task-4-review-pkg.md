BASE ce4a27c4b17a16d53900351dee348e1a99c0e955 HEAD bbe3e7458d7f94a9f36039c1b72d43cbdee96223

 .superpowers/sdd/progress.md      |   8 +  .superpowers/sdd/task-4-report.md | 143 +++++++++++++  internal/certs/ca.go              | 418 ++++++++++++++++++++++++++++++++++++++  internal/certs/ca_test.go         | 310 ++++++++++++++++++++++++++++  internal/certs/crypto_box.go      |  73 +++++++  internal/certs/leaf_cache.go      | 145 +++++++++++++  internal/certs/leaf_cache_test.go | 123 +++++++++++  internal/store/certificates.go    | 182 +++++++++++++++++  8 files changed, 1402 insertions(+)
diff --git a/.superpowers/sdd/progress.md b/.superpowers/sdd/progress.md
index 7afb9c2..4c34dd6 100644
--- a/.superpowers/sdd/progress.md
+++ b/.superpowers/sdd/progress.md
@@ -2,5 +2,13 @@
 Branch: feature/wsp-v1
 Worktree: D:\Grok\WSP\.worktrees\wsp-v1
 Started: 2026-07-27
 Base commit: 23e1455
 
+Task 1: complete (commits 23e1455..faa8b7b, review clean)
+
+Task 2: complete (commits faa8b7b..ec3bec8, review clean after fixes)
+
+Task 3: complete (commits ec3bec8..ce4a27c, review clean after fixes)
+
+Task 4: complete (commit fe9f6cc, self-signed CA + MITM leaf cache)
+
diff --git a/.superpowers/sdd/task-4-report.md b/.superpowers/sdd/task-4-report.md
new file mode 100644
index 0000000..b1b0500
--- /dev/null
+++ b/.superpowers/sdd/task-4-report.md
@@ -0,0 +1,143 @@
+# Task 4 Report: Certificate CA + encrypted key storage + leaf cache
+
+**Status:** DONE  
+**Branch:** `feature/wsp-v1`  
+**Commit:** `fe9f6cc` ΓÇö `feat: self-signed CA generation and MITM leaf cache`  
+**Author:** WSP Dev \<dev@wsp.local\>  
+**Date:** 2026-07-27
+
+---
+
+## Summary
+
+Implemented `internal/certs` with AES-GCM encryption of CA private keys (key derived from `WSP_DATA_KEY` via SHA-256), ECDSA P-256 self-signed CA generation (~10y), on-demand MITM leaf signing (SAN DNS/IP, ~48h), and an in-memory LRU leaf cache (max 1024). Added store methods for the `certificates` table (activate one CA at a time).
+
+---
+
+## Deliverables
+
+| Path | Purpose |
+|------|---------|
+| `internal/certs/crypto_box.go` | `DeriveKey` / `Seal` / `Open` (AES-256-GCM) |
+| `internal/certs/ca.go` | `Provider`, `GenerateSelfSignedCA`, `ActiveCA`, `SignHost` |
+| `internal/certs/leaf_cache.go` | Thread-safe LRU leaf cache (max 1024) |
+| `internal/certs/ca_test.go` | Unit tests: crypto box, CA ΓåÆ SignHost ΓåÆ chain verify |
+| `internal/certs/leaf_cache_test.go` | Unit tests: LRU eviction, expiry, clear |
+| `internal/store/certificates.go` | `InsertActiveCertificate`, `GetActiveCertificate`, `GetCertificateByID` |
+
+---
+
+## Certs API
+
+```go
+type Provider struct { /* store, dataKey, cache, in-memory CA */ }
+
+func NewProvider(store *store.Store, dataKey string) (*Provider, error)
+func (p *Provider) GenerateSelfSignedCA(ctx context.Context, name string) (CertMeta, error)
+func (p *Provider) ActiveCA(ctx context.Context) (certPEM []byte, ok bool, err error)
+func (p *Provider) SignHost(host string) (*tls.Certificate, error)
+
+func DeriveKey(dataKey string) ([]byte, error) // min 16 chars ΓåÆ SHA-256 ΓåÆ 32 bytes
+func Seal(key, plaintext []byte) ([]byte, error)
+func Open(key, box []byte) ([]byte, error)
+
+func NewLeafCache(max int) *LeafCache
+func (c *LeafCache) Get(host string) (*tls.Certificate, bool)
+func (c *LeafCache) Put(host string, cert *tls.Certificate, notAfter time.Time)
+func (c *LeafCache) Clear()
+```
+
+### Crypto box
+- `WSP_DATA_KEY` minimum **16 characters**; rejected if shorter
+- Key material: **SHA-256(dataKey)** ΓåÆ 32-byte AES key
+- Algorithm: **AES-256-GCM**; storage format `nonce || ciphertext||tag`
+- Used only for CA private key PEM at rest (`key_pem_encrypted` BYTEA)
+
+### CA generation
+- Algorithm: **ECDSA P-256** (perf preference over RSA 4096)
+- Validity: **~10 years** (`DefaultCAValidity`)
+- IsCA, path length 0, key usage cert sign / CRL sign / digital signature
+- Fingerprint: hex SHA-256 of DER certificate
+- On generate: encrypt key, `InsertActiveCertificate` (deactivates prior active CA in a TX), hold key in memory, **clear leaf cache**
+
+### Leaf certificates
+- ECDSA P-256 key per host
+- Validity: **~48 hours** (`DefaultLeafValidity`)
+- SAN: **DNS=host** for hostnames; **IP SAN** when host parses as IP
+- Host may include port (`example.com:443` ΓåÆ stripped via `SplitHostPort`)
+- `tls.Certificate` includes leaf DER + CA DER for chain presentation
+- Cached under normalized host name
+
+### Leaf cache
+- LRU max **1024** (`DefaultLeafCacheSize`)
+- Entries expire at leaf `NotAfter` minus 5-minute safety margin
+- Thread-safe; nil-safe methods
+
+### In-memory CA key
+- After `GenerateSelfSignedCA`, CA cert+key stay in process memory for `SignHost`
+- If cold process: `SignHost` / `ActiveCA` load active row from store and decrypt key (`loadActiveCA`)
+- `store == nil` allowed for unit tests (in-memory only; no persistence)
+
+---
+
+## Store methods added
+
+| Method | Behavior |
+|--------|----------|
+| `InsertActiveCertificate` | TX: deactivate existing active of same kind ΓåÆ insert active row |
+| `GetActiveCertificate` | Active CA by kind; `ok=false` if none |
+| `GetCertificateByID` | Full row including encrypted key (server-side) |
+
+Partial unique index `certificates_one_active_ca_idx` remains the DB-level guarantee of a single active self-signed CA.
+
+---
+
+## Verification
+
+| Check | Result |
+|-------|--------|
+| `go test ./internal/certs/` | PASS |
+| `go test ./internal/store/` | PASS |
+| `go test ./...` | PASS |
+| Live Postgres insert/load of CA | **Not run** ΓÇö unit tests use `store=nil` in-memory path |
+
+### Unit coverage highlights
+- Seal/Open round-trip; wrong key fails; unique nonces
+- DeriveKey min length + 32-byte output
+- Generate CA ΓåÆ `SignHost("example.com")` ΓåÆ `VerifyHostname` + `x509.Verify` chain to CA
+- Leaf ~48h, CA ~10y, ECDSA P-256
+- Cache hit reuses serial; CA rotation clears cache and re-signs under new CA
+- LRU eviction (max capacity), expired entries, Clear
+
+---
+
+## Self-review
+
+### Matches task brief
+- [x] `internal/certs/crypto_box.go`, `ca.go`, `leaf_cache.go`
+- [x] Tests: `ca_test.go`, `leaf_cache_test.go`
+- [x] AES-GCM box from `WSP_DATA_KEY` (min 16, SHA-256 ΓåÆ 32 bytes)
+- [x] ECDSA P-256 CA, PEM cert + encrypted key storage via store
+- [x] Leaf LRU max 1024, SAN DNS=host, ~48h validity
+- [x] Unit test generate CA ΓåÆ SignHost ΓåÆ verify chain
+- [x] Commit `feat: self-signed CA generation and MITM leaf cache`
+- [x] Author WSP Dev \<dev@wsp.local\>
+- [x] Store methods for `certificates` table
+- [x] CA key held in memory after generate/load for `SignHost`
+- [x] No Task 5+ (policy, proxy, etc.)
+
+### Concerns / follow-ups
+1. **No live DB integration test** for insert/decrypt path ΓÇö add `//go:build integration` when Postgres is available (mirror auth tests).
+2. **`NewProvider` does not pre-load CA** ΓÇö first `SignHost` after restart decrypts from DB (acceptable; note for cold-start latency).
+3. **CA private key never returned from API paths** ΓÇö only `ActiveCA` public PEM; enforce again in management handlers later.
+4. **Leaf clock skew**: notBefore is `now - 5m`; CA uses `now - 1h`.
+5. **No HSM / customer subordinate CA** ΓÇö design allows future `Provider` swap; not in scope.
+
+---
+
+## Out of scope (not done)
+
+- Management `/api/v1/certificates` HTTP handlers / UI
+- Wiring `certs.Provider` into `cmd/wsp` or MITM proxy (Task 6+)
+- Policy engine (Task 5)
+- Customer-uploaded intermediate / subordinate CA
diff --git a/internal/certs/ca.go b/internal/certs/ca.go
new file mode 100644
index 0000000..a17411e
--- /dev/null
+++ b/internal/certs/ca.go
@@ -0,0 +1,418 @@
+package certs
+
+import (
+	"context"
+	"crypto"
+	"crypto/ecdsa"
+	"crypto/elliptic"
+	"crypto/rand"
+	"crypto/sha256"
+	"crypto/tls"
+	"crypto/x509"
+	"crypto/x509/pkix"
+	"encoding/hex"
+	"encoding/pem"
+	"errors"
+	"fmt"
+	"math/big"
+	"net"
+	"sync"
+	"time"
+
+	"github.com/google/uuid"
+
+	"github.com/wsp-security/wsp/internal/store"
+)
+
+// CA and leaf validity defaults.
+const (
+	// DefaultCAValidity is how long a generated self-signed CA remains valid.
+	DefaultCAValidity = 10 * 365 * 24 * time.Hour // ~10 years
+	// DefaultLeafValidity is how long MITM leaf certificates remain valid.
+	DefaultLeafValidity = 48 * time.Hour
+)
+
+// CertMeta is public metadata for a stored CA certificate (no private key).
+type CertMeta struct {
+	ID                uuid.UUID `json:"id"`
+	Name              string    `json:"name"`
+	Kind              string    `json:"kind"`
+	FingerprintSHA256 string    `json:"fingerprint_sha256"`
+	NotBefore         time.Time `json:"not_before"`
+	NotAfter          time.Time `json:"not_after"`
+	IsActive          bool      `json:"is_active"`
+	CreatedAt         time.Time `json:"created_at"`
+}
+
+// Provider generates and stores a self-signed CA, and signs short-lived leaf
+// certificates for MITM. The active CA private key is held in memory after
+// generation or first load/decrypt from the store.
+type Provider struct {
+	store   *store.Store
+	dataKey []byte
+	cache   *LeafCache
+
+	mu        sync.RWMutex
+	caCert    *x509.Certificate
+	caKey     crypto.Signer
+	caCertPEM []byte
+}
+
+// NewProvider builds a certs.Provider. dataKey is the WSP_DATA_KEY string
+// (min 16 chars); it is hashed to a 32-byte AES key for encrypting CA private keys.
+// store may be nil for in-memory-only unit tests (GenerateSelfSignedCA will not persist).
+func NewProvider(s *store.Store, dataKey string) (*Provider, error) {
+	key, err := DeriveKey(dataKey)
+	if err != nil {
+		return nil, err
+	}
+	return &Provider{
+		store:   s,
+		dataKey: key,
+		cache:   NewLeafCache(DefaultLeafCacheSize),
+	}, nil
+}
+
+// GenerateSelfSignedCA creates an ECDSA P-256 self-signed CA (Γëê10y), encrypts the
+// private key with the data key, stores it as the active CA when a store is configured,
+// and keeps the CA key in memory for SignHost.
+func (p *Provider) GenerateSelfSignedCA(ctx context.Context, name string) (CertMeta, error) {
+	if p == nil {
+		return CertMeta{}, errors.New("provider is nil")
+	}
+	if name == "" {
+		return CertMeta{}, errors.New("CA name is required")
+	}
+
+	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
+	if err != nil {
+		return CertMeta{}, fmt.Errorf("generate CA key: %w", err)
+	}
+
+	now := time.Now().UTC()
+	notBefore := now.Add(-1 * time.Hour) // clock skew
+	notAfter := now.Add(DefaultCAValidity)
+
+	serial, err := randomSerial()
+	if err != nil {
+		return CertMeta{}, err
+	}
+
+	tmpl := &x509.Certificate{
+		SerialNumber: serial,
+		Subject: pkix.Name{
+			CommonName:   name,
+			Organization: []string{"WSP"},
+		},
+		NotBefore:             notBefore,
+		NotAfter:              notAfter,
+		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
+		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
+		BasicConstraintsValid: true,
+		IsCA:                  true,
+		MaxPathLen:            0,
+		MaxPathLenZero:        true,
+	}
+
+	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
+	if err != nil {
+		return CertMeta{}, fmt.Errorf("create CA certificate: %w", err)
+	}
+	caCert, err := x509.ParseCertificate(der)
+	if err != nil {
+		return CertMeta{}, fmt.Errorf("parse CA certificate: %w", err)
+	}
+
+	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
+	keyDER, err := x509.MarshalECPrivateKey(priv)
+	if err != nil {
+		return CertMeta{}, fmt.Errorf("marshal CA key: %w", err)
+	}
+	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
+
+	encKey, err := Seal(p.dataKey, keyPEM)
+	if err != nil {
+		return CertMeta{}, fmt.Errorf("encrypt CA key: %w", err)
+	}
+
+	fp := sha256.Sum256(der)
+	fpHex := hex.EncodeToString(fp[:])
+
+	meta := CertMeta{
+		Name:              name,
+		Kind:              store.CertKindSelfSignedCA,
+		FingerprintSHA256: fpHex,
+		NotBefore:         caCert.NotBefore,
+		NotAfter:          caCert.NotAfter,
+		IsActive:          true,
+	}
+
+	if p.store != nil {
+		row, err := p.store.InsertActiveCertificate(ctx, store.Certificate{
+			Name:              name,
+			Kind:              store.CertKindSelfSignedCA,
+			CertPEM:           string(certPEM),
+			KeyPEMEncrypted:   encKey,
+			FingerprintSHA256: fpHex,
+			NotBefore:         caCert.NotBefore,
+			NotAfter:          caCert.NotAfter,
+		})
+		if err != nil {
+			return CertMeta{}, err
+		}
+		meta.ID = row.ID
+		meta.CreatedAt = row.CreatedAt
+		meta.IsActive = row.IsActive
+	}
+
+	// Install active CA in memory and drop leaves signed by any previous CA.
+	p.mu.Lock()
+	p.caCert = caCert
+	p.caKey = priv
+	p.caCertPEM = certPEM
+	p.mu.Unlock()
+	p.cache.Clear()
+
+	return meta, nil
+}
+
+// ActiveCA returns the PEM-encoded public certificate of the active CA.
+// ok is false when no CA is loaded or stored.
+func (p *Provider) ActiveCA(ctx context.Context) (certPEM []byte, ok bool, err error) {
+	if p == nil {
+		return nil, false, errors.New("provider is nil")
+	}
+
+	p.mu.RLock()
+	if len(p.caCertPEM) > 0 {
+		out := append([]byte(nil), p.caCertPEM...)
+		p.mu.RUnlock()
+		return out, true, nil
+	}
+	p.mu.RUnlock()
+
+	if err := p.loadActiveCA(ctx); err != nil {
+		return nil, false, err
+	}
+
+	p.mu.RLock()
+	defer p.mu.RUnlock()
+	if len(p.caCertPEM) == 0 {
+		return nil, false, nil
+	}
+	return append([]byte(nil), p.caCertPEM...), true, nil
+}
+
+// SignHost returns a leaf TLS certificate for host (SAN DNS or IP), signed by
+// the active CA. Results are cached in an LRU of size DefaultLeafCacheSize.
+// The active CA key must be available in memory or loadable from the store.
+func (p *Provider) SignHost(host string) (*tls.Certificate, error) {
+	if p == nil {
+		return nil, errors.New("provider is nil")
+	}
+	host = normalizeHost(host)
+	if host == "" {
+		return nil, errors.New("host is required")
+	}
+
+	if cert, ok := p.cache.Get(host); ok {
+		return cert, nil
+	}
+
+	if err := p.ensureCALoaded(context.Background()); err != nil {
+		return nil, err
+	}
+
+	p.mu.RLock()
+	caCert := p.caCert
+	caKey := p.caKey
+	caCertPEM := p.caCertPEM
+	p.mu.RUnlock()
+	if caCert == nil || caKey == nil {
+		return nil, errors.New("no active CA")
+	}
+
+	leaf, notAfter, err := signLeaf(caCert, caKey, host)
+	if err != nil {
+		return nil, err
+	}
+
+	// tls.Certificate with leaf + CA for chain presentation.
+	tlsCert := &tls.Certificate{
+		Certificate: [][]byte{leaf.Certificate[0], caCert.Raw},
+		PrivateKey:  leaf.PrivateKey,
+		Leaf:        leaf.Leaf,
+	}
+	// Keep caCertPEM referenced so callers who only have leaf still have chain DER.
+	_ = caCertPEM
+
+	p.cache.Put(host, tlsCert, notAfter)
+	return tlsCert, nil
+}
+
+// ensureCALoaded loads and decrypts the active CA into memory if not already present.
+func (p *Provider) ensureCALoaded(ctx context.Context) error {
+	p.mu.RLock()
+	ready := p.caCert != nil && p.caKey != nil
+	p.mu.RUnlock()
+	if ready {
+		return nil
+	}
+	return p.loadActiveCA(ctx)
+}
+
+// loadActiveCA fetches the active CA from the store, decrypts the key, and installs it.
+func (p *Provider) loadActiveCA(ctx context.Context) error {
+	if p.store == nil {
+		return nil // in-memory-only mode; GenerateSelfSignedCA must have been called
+	}
+
+	row, ok, err := p.store.GetActiveCertificate(ctx, store.CertKindSelfSignedCA)
+	if err != nil {
+		return err
+	}
+	if !ok {
+		return nil
+	}
+
+	keyPEM, err := Open(p.dataKey, row.KeyPEMEncrypted)
+	if err != nil {
+		return fmt.Errorf("decrypt CA key: %w", err)
+	}
+
+	caCert, caKey, err := parseCAMaterial([]byte(row.CertPEM), keyPEM)
+	if err != nil {
+		return err
+	}
+
+	p.mu.Lock()
+	p.caCert = caCert
+	p.caKey = caKey
+	p.caCertPEM = []byte(row.CertPEM)
+	p.mu.Unlock()
+	return nil
+}
+
+func parseCAMaterial(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
+	block, _ := pem.Decode(certPEM)
+	if block == nil || block.Type != "CERTIFICATE" {
+		return nil, nil, errors.New("invalid CA cert PEM")
+	}
+	caCert, err := x509.ParseCertificate(block.Bytes)
+	if err != nil {
+		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
+	}
+
+	keyBlock, _ := pem.Decode(keyPEM)
+	if keyBlock == nil {
+		return nil, nil, errors.New("invalid CA key PEM")
+	}
+
+	var signer crypto.Signer
+	switch keyBlock.Type {
+	case "EC PRIVATE KEY":
+		k, err := x509.ParseECPrivateKey(keyBlock.Bytes)
+		if err != nil {
+			return nil, nil, fmt.Errorf("parse EC private key: %w", err)
+		}
+		signer = k
+	case "PRIVATE KEY":
+		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
+		if err != nil {
+			return nil, nil, fmt.Errorf("parse PKCS8 private key: %w", err)
+		}
+		s, ok := k.(crypto.Signer)
+		if !ok {
+			return nil, nil, errors.New("CA key is not a signer")
+		}
+		signer = s
+	case "RSA PRIVATE KEY":
+		k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
+		if err != nil {
+			return nil, nil, fmt.Errorf("parse RSA private key: %w", err)
+		}
+		signer = k
+	default:
+		return nil, nil, fmt.Errorf("unsupported CA key PEM type %q", keyBlock.Type)
+	}
+
+	return caCert, signer, nil
+}
+
+func signLeaf(caCert *x509.Certificate, caKey crypto.Signer, host string) (*tls.Certificate, time.Time, error) {
+	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
+	if err != nil {
+		return nil, time.Time{}, fmt.Errorf("generate leaf key: %w", err)
+	}
+
+	now := time.Now().UTC()
+	notBefore := now.Add(-5 * time.Minute)
+	notAfter := now.Add(DefaultLeafValidity)
+
+	serial, err := randomSerial()
+	if err != nil {
+		return nil, time.Time{}, err
+	}
+
+	tmpl := &x509.Certificate{
+		SerialNumber: serial,
+		Subject: pkix.Name{
+			CommonName: host,
+		},
+		NotBefore:             notBefore,
+		NotAfter:              notAfter,
+		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
+		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
+		BasicConstraintsValid: true,
+		IsCA:                  false,
+	}
+
+	if ip := net.ParseIP(host); ip != nil {
+		tmpl.IPAddresses = []net.IP{ip}
+	} else {
+		tmpl.DNSNames = []string{host}
+	}
+
+	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
+	if err != nil {
+		return nil, time.Time{}, fmt.Errorf("create leaf certificate: %w", err)
+	}
+	leafCert, err := x509.ParseCertificate(der)
+	if err != nil {
+		return nil, time.Time{}, fmt.Errorf("parse leaf certificate: %w", err)
+	}
+
+	return &tls.Certificate{
+		Certificate: [][]byte{der},
+		PrivateKey:  priv,
+		Leaf:        leafCert,
+	}, notAfter, nil
+}
+
+func randomSerial() (*big.Int, error) {
+	// 128-bit positive serial.
+	limit := new(big.Int).Lsh(big.NewInt(1), 128)
+	n, err := rand.Int(rand.Reader, limit)
+	if err != nil {
+		return nil, fmt.Errorf("serial: %w", err)
+	}
+	// Avoid serial 0.
+	if n.Sign() == 0 {
+		n = big.NewInt(1)
+	}
+	return n, nil
+}
+
+// normalizeHost strips a trailing port if present (host:port ΓåÆ host).
+// IPv6 bracket form [addr]:port is supported.
+func normalizeHost(host string) string {
+	if host == "" {
+		return ""
+	}
+	// host:port or [ipv6]:port
+	if h, _, err := net.SplitHostPort(host); err == nil {
+		return h
+	}
+	// Bare IPv6 without brackets ΓÇö leave as-is for ParseIP in signLeaf.
+	return host
+}
diff --git a/internal/certs/ca_test.go b/internal/certs/ca_test.go
new file mode 100644
index 0000000..66305c9
--- /dev/null
+++ b/internal/certs/ca_test.go
@@ -0,0 +1,310 @@
+package certs
+
+import (
+	"context"
+	"crypto/ecdsa"
+	"crypto/sha256"
+	"crypto/x509"
+	"encoding/pem"
+	"testing"
+	"time"
+)
+
+const testDataKey = "test-data-key-16b" // exactly 16 chars minimum
+
+func TestDeriveKeyMinLength(t *testing.T) {
+	if _, err := DeriveKey("short"); err == nil {
+		t.Fatal("DeriveKey(short) expected error")
+	}
+	key, err := DeriveKey(testDataKey)
+	if err != nil {
+		t.Fatalf("DeriveKey: %v", err)
+	}
+	if len(key) != 32 {
+		t.Fatalf("key len = %d, want 32", len(key))
+	}
+	// Deterministic.
+	key2, err := DeriveKey(testDataKey)
+	if err != nil {
+		t.Fatalf("DeriveKey #2: %v", err)
+	}
+	if sha256.Sum256(key) != sha256.Sum256(key2) {
+		t.Fatal("DeriveKey not deterministic")
+	}
+}
+
+func TestSealOpenRoundTrip(t *testing.T) {
+	key, err := DeriveKey(testDataKey)
+	if err != nil {
+		t.Fatalf("DeriveKey: %v", err)
+	}
+	plain := []byte("-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----")
+	box, err := Seal(key, plain)
+	if err != nil {
+		t.Fatalf("Seal: %v", err)
+	}
+	if len(box) <= len(plain) {
+		t.Fatalf("box should be longer than plaintext (nonce+tag), got %d vs %d", len(box), len(plain))
+	}
+	out, err := Open(key, box)
+	if err != nil {
+		t.Fatalf("Open: %v", err)
+	}
+	if string(out) != string(plain) {
+		t.Fatalf("Open = %q, want %q", out, plain)
+	}
+	// Wrong key fails.
+	other, _ := DeriveKey("other-data-key!!")
+	if _, err := Open(other, box); err == nil {
+		t.Fatal("Open with wrong key expected error")
+	}
+	// Seal produces unique nonces.
+	box2, err := Seal(key, plain)
+	if err != nil {
+		t.Fatalf("Seal #2: %v", err)
+	}
+	if string(box) == string(box2) {
+		t.Fatal("Seal should use random nonces")
+	}
+}
+
+func TestNewProviderRejectsShortKey(t *testing.T) {
+	if _, err := NewProvider(nil, "tooshort"); err == nil {
+		t.Fatal("NewProvider with short key expected error")
+	}
+}
+
+func TestGenerateCA_SignHost_VerifyChain(t *testing.T) {
+	p, err := NewProvider(nil, testDataKey)
+	if err != nil {
+		t.Fatalf("NewProvider: %v", err)
+	}
+
+	ctx := context.Background()
+	meta, err := p.GenerateSelfSignedCA(ctx, "WSP Test CA")
+	if err != nil {
+		t.Fatalf("GenerateSelfSignedCA: %v", err)
+	}
+	if meta.Name != "WSP Test CA" {
+		t.Fatalf("meta.Name = %q", meta.Name)
+	}
+	if meta.FingerprintSHA256 == "" {
+		t.Fatal("empty fingerprint")
+	}
+	if !meta.IsActive {
+		t.Fatal("meta.IsActive = false")
+	}
+	// ~10 years
+	if meta.NotAfter.Sub(meta.NotBefore) < 9*365*24*time.Hour {
+		t.Fatalf("CA validity too short: %v", meta.NotAfter.Sub(meta.NotBefore))
+	}
+
+	certPEM, ok, err := p.ActiveCA(ctx)
+	if err != nil {
+		t.Fatalf("ActiveCA: %v", err)
+	}
+	if !ok || len(certPEM) == 0 {
+		t.Fatal("ActiveCA returned empty")
+	}
+	block, _ := pem.Decode(certPEM)
+	if block == nil {
+		t.Fatal("ActiveCA not valid PEM")
+	}
+	caCert, err := x509.ParseCertificate(block.Bytes)
+	if err != nil {
+		t.Fatalf("parse CA: %v", err)
+	}
+	if !caCert.IsCA {
+		t.Fatal("CA cert IsCA = false")
+	}
+	// Prefer ECDSA P-256
+	if _, ok := caCert.PublicKey.(*ecdsa.PublicKey); !ok {
+		t.Fatalf("CA public key type %T, want *ecdsa.PublicKey", caCert.PublicKey)
+	}
+	if pub, ok := caCert.PublicKey.(*ecdsa.PublicKey); ok {
+		if pub.Curve.Params().Name != "P-256" {
+			t.Fatalf("CA curve = %s, want P-256", pub.Curve.Params().Name)
+		}
+	}
+
+	// Sign leaf for example.com
+	leafTLS, err := p.SignHost("example.com")
+	if err != nil {
+		t.Fatalf("SignHost: %v", err)
+	}
+	if leafTLS == nil || leafTLS.Leaf == nil {
+		t.Fatal("SignHost returned nil leaf")
+	}
+	if len(leafTLS.Certificate) < 1 {
+		t.Fatal("leaf Certificate DER missing")
+	}
+
+	leaf := leafTLS.Leaf
+	if err := leaf.VerifyHostname("example.com"); err != nil {
+		t.Fatalf("VerifyHostname: %v", err)
+	}
+	// SAN DNS
+	foundDNS := false
+	for _, d := range leaf.DNSNames {
+		if d == "example.com" {
+			foundDNS = true
+			break
+		}
+	}
+	if !foundDNS {
+		t.Fatalf("DNSNames = %v, want example.com", leaf.DNSNames)
+	}
+
+	// ~48h validity
+	validFor := leaf.NotAfter.Sub(leaf.NotBefore)
+	if validFor < 40*time.Hour || validFor > 55*time.Hour {
+		t.Fatalf("leaf validity = %v, want ~48h", validFor)
+	}
+
+	// Verify chain: leaf ΓåÆ CA
+	roots := x509.NewCertPool()
+	roots.AddCert(caCert)
+	opts := x509.VerifyOptions{
+		DNSName: "example.com",
+		Roots:   roots,
+		// Leaf is for server auth.
+		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
+	}
+	// If chain includes intermediate (CA DER as second), use Intermediates.
+	inter := x509.NewCertPool()
+	if len(leafTLS.Certificate) > 1 {
+		if ic, err := x509.ParseCertificate(leafTLS.Certificate[1]); err == nil {
+			inter.AddCert(ic)
+		}
+	}
+	opts.Intermediates = inter
+
+	if _, err := leaf.Verify(opts); err != nil {
+		t.Fatalf("chain verify: %v", err)
+	}
+
+	// Cache hit returns same material
+	leaf2, err := p.SignHost("example.com")
+	if err != nil {
+		t.Fatalf("SignHost cache: %v", err)
+	}
+	if leaf2.Leaf.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
+		t.Fatal("cache miss regenerated leaf serial")
+	}
+
+	// Different host gets different cert
+	other, err := p.SignHost("other.example")
+	if err != nil {
+		t.Fatalf("SignHost other: %v", err)
+	}
+	if other.Leaf.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
+		t.Fatal("different hosts share serial")
+	}
+	if err := other.Leaf.VerifyHostname("other.example"); err != nil {
+		t.Fatalf("other VerifyHostname: %v", err)
+	}
+}
+
+func TestSignHostRequiresCA(t *testing.T) {
+	p, err := NewProvider(nil, testDataKey)
+	if err != nil {
+		t.Fatalf("NewProvider: %v", err)
+	}
+	if _, err := p.SignHost("example.com"); err == nil {
+		t.Fatal("SignHost without CA expected error")
+	}
+}
+
+func TestSignHostEmptyHost(t *testing.T) {
+	p, err := NewProvider(nil, testDataKey)
+	if err != nil {
+		t.Fatalf("NewProvider: %v", err)
+	}
+	if _, err := p.GenerateSelfSignedCA(context.Background(), "CA"); err != nil {
+		t.Fatalf("GenerateSelfSignedCA: %v", err)
+	}
+	if _, err := p.SignHost(""); err == nil {
+		t.Fatal("SignHost empty expected error")
+	}
+}
+
+func TestSignHostStripsPort(t *testing.T) {
+	p, err := NewProvider(nil, testDataKey)
+	if err != nil {
+		t.Fatalf("NewProvider: %v", err)
+	}
+	if _, err := p.GenerateSelfSignedCA(context.Background(), "CA"); err != nil {
+		t.Fatalf("GenerateSelfSignedCA: %v", err)
+	}
+	cert, err := p.SignHost("example.com:443")
+	if err != nil {
+		t.Fatalf("SignHost: %v", err)
+	}
+	if err := cert.Leaf.VerifyHostname("example.com"); err != nil {
+		t.Fatalf("VerifyHostname: %v", err)
+	}
+}
+
+func TestSignHostIP(t *testing.T) {
+	p, err := NewProvider(nil, testDataKey)
+	if err != nil {
+		t.Fatalf("NewProvider: %v", err)
+	}
+	if _, err := p.GenerateSelfSignedCA(context.Background(), "CA"); err != nil {
+		t.Fatalf("GenerateSelfSignedCA: %v", err)
+	}
+	cert, err := p.SignHost("127.0.0.1")
+	if err != nil {
+		t.Fatalf("SignHost: %v", err)
+	}
+	if err := cert.Leaf.VerifyHostname("127.0.0.1"); err != nil {
+		t.Fatalf("VerifyHostname IP: %v", err)
+	}
+	if len(cert.Leaf.IPAddresses) == 0 {
+		t.Fatal("expected IP SAN")
+	}
+}
+
+func TestCARotationClearsLeafCache(t *testing.T) {
+	p, err := NewProvider(nil, testDataKey)
+	if err != nil {
+		t.Fatalf("NewProvider: %v", err)
+	}
+	ctx := context.Background()
+	if _, err := p.GenerateSelfSignedCA(ctx, "CA1"); err != nil {
+		t.Fatalf("CA1: %v", err)
+	}
+	leaf1, err := p.SignHost("example.com")
+	if err != nil {
+		t.Fatalf("SignHost: %v", err)
+	}
+	if _, err := p.GenerateSelfSignedCA(ctx, "CA2"); err != nil {
+		t.Fatalf("CA2: %v", err)
+	}
+	leaf2, err := p.SignHost("example.com")
+	if err != nil {
+		t.Fatalf("SignHost after rotate: %v", err)
+	}
+	if leaf1.Leaf.SerialNumber.Cmp(leaf2.Leaf.SerialNumber) == 0 {
+		t.Fatal("leaf serial unchanged after CA rotation (cache not cleared?)")
+	}
+	// New leaf must chain to new CA
+	certPEM, ok, err := p.ActiveCA(ctx)
+	if err != nil || !ok {
+		t.Fatalf("ActiveCA: ok=%v err=%v", ok, err)
+	}
+	block, _ := pem.Decode(certPEM)
+	caCert, err := x509.ParseCertificate(block.Bytes)
+	if err != nil {
+		t.Fatalf("parse CA: %v", err)
+	}
+	roots := x509.NewCertPool()
+	roots.AddCert(caCert)
+	if _, err := leaf2.Leaf.Verify(x509.VerifyOptions{
+		DNSName:   "example.com",
+		Roots:     roots,
+		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
+	}); err != nil {
+		t.Fatalf("verify under new CA: %v", err)
+	}
+}
diff --git a/internal/certs/crypto_box.go b/internal/certs/crypto_box.go
new file mode 100644
index 0000000..d1072dd
--- /dev/null
+++ b/internal/certs/crypto_box.go
@@ -0,0 +1,73 @@
+// Package certs provides self-signed CA generation, encrypted key storage,
+// and on-demand MITM leaf certificates with an in-memory LRU cache.
+package certs
+
+import (
+	"crypto/aes"
+	"crypto/cipher"
+	"crypto/rand"
+	"crypto/sha256"
+	"errors"
+	"fmt"
+	"io"
+)
+
+// MinDataKeyLen is the minimum accepted length of WSP_DATA_KEY (UTF-8 bytes).
+const MinDataKeyLen = 16
+
+// DeriveKey turns a user-supplied data key (WSP_DATA_KEY) into a 32-byte AES key
+// via SHA-256. Requires at least MinDataKeyLen characters.
+func DeriveKey(dataKey string) ([]byte, error) {
+	if len(dataKey) < MinDataKeyLen {
+		return nil, fmt.Errorf("data key must be at least %d characters", MinDataKeyLen)
+	}
+	sum := sha256.Sum256([]byte(dataKey))
+	return sum[:], nil
+}
+
+// Seal encrypts plaintext with AES-256-GCM using key (must be 16/24/32 bytes).
+// The returned box is nonce || ciphertext||tag.
+func Seal(key, plaintext []byte) ([]byte, error) {
+	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
+		return nil, errors.New("AES key must be 16, 24, or 32 bytes")
+	}
+	block, err := aes.NewCipher(key)
+	if err != nil {
+		return nil, fmt.Errorf("aes cipher: %w", err)
+	}
+	gcm, err := cipher.NewGCM(block)
+	if err != nil {
+		return nil, fmt.Errorf("gcm: %w", err)
+	}
+	nonce := make([]byte, gcm.NonceSize())
+	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
+		return nil, fmt.Errorf("nonce: %w", err)
+	}
+	// Seal appends ciphertext+tag to the destination; prepend nonce for storage.
+	return gcm.Seal(nonce, nonce, plaintext, nil), nil
+}
+
+// Open decrypts a box produced by Seal (nonce || ciphertext||tag).
+func Open(key, box []byte) ([]byte, error) {
+	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
+		return nil, errors.New("AES key must be 16, 24, or 32 bytes")
+	}
+	block, err := aes.NewCipher(key)
+	if err != nil {
+		return nil, fmt.Errorf("aes cipher: %w", err)
+	}
+	gcm, err := cipher.NewGCM(block)
+	if err != nil {
+		return nil, fmt.Errorf("gcm: %w", err)
+	}
+	nonceSize := gcm.NonceSize()
+	if len(box) < nonceSize {
+		return nil, errors.New("ciphertext too short")
+	}
+	nonce, ciphertext := box[:nonceSize], box[nonceSize:]
+	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
+	if err != nil {
+		return nil, fmt.Errorf("decrypt: %w", err)
+	}
+	return plain, nil
+}
diff --git a/internal/certs/leaf_cache.go b/internal/certs/leaf_cache.go
new file mode 100644
index 0000000..24d04f0
--- /dev/null
+++ b/internal/certs/leaf_cache.go
@@ -0,0 +1,145 @@
+package certs
+
+import (
+	"container/list"
+	"crypto/tls"
+	"sync"
+	"time"
+)
+
+// DefaultLeafCacheSize is the maximum number of host leaf certificates retained.
+const DefaultLeafCacheSize = 1024
+
+// leafCacheEntry holds a cached leaf and when we consider it stale for MITM reuse.
+type leafCacheEntry struct {
+	host      string
+	cert      *tls.Certificate
+	notAfter  time.Time
+	expiresAt time.Time // when the cache entry should be treated as expired
+}
+
+// LeafCache is a thread-safe LRU cache of per-host leaf certificates.
+type LeafCache struct {
+	mu      sync.Mutex
+	max     int
+	ll      *list.List // front = most recently used
+	entries map[string]*list.Element
+}
+
+// NewLeafCache returns an LRU leaf cache with the given max size.
+// Non-positive max uses DefaultLeafCacheSize.
+func NewLeafCache(max int) *LeafCache {
+	if max <= 0 {
+		max = DefaultLeafCacheSize
+	}
+	return &LeafCache{
+		max:     max,
+		ll:      list.New(),
+		entries: make(map[string]*list.Element, max),
+	}
+}
+
+// Get returns a cached certificate for host if present and not expired.
+// Expired entries are removed.
+func (c *LeafCache) Get(host string) (*tls.Certificate, bool) {
+	if c == nil || host == "" {
+		return nil, false
+	}
+	c.mu.Lock()
+	defer c.mu.Unlock()
+
+	el, ok := c.entries[host]
+	if !ok {
+		return nil, false
+	}
+	ent := el.Value.(*leafCacheEntry)
+	now := time.Now()
+	if !ent.expiresAt.IsZero() && !now.Before(ent.expiresAt) {
+		c.removeElement(el)
+		return nil, false
+	}
+	// Also treat as miss if the cert itself is past NotAfter.
+	if !ent.notAfter.IsZero() && !now.Before(ent.notAfter) {
+		c.removeElement(el)
+		return nil, false
+	}
+	c.ll.MoveToFront(el)
+	return ent.cert, true
+}
+
+// Put stores cert for host, evicting the least-recently-used entry if at capacity.
+// notAfter is the leaf certificate's validity end; the entry is considered expired
+// a short safety margin before that (or immediately if already past).
+func (c *LeafCache) Put(host string, cert *tls.Certificate, notAfter time.Time) {
+	if c == nil || host == "" || cert == nil {
+		return
+	}
+	c.mu.Lock()
+	defer c.mu.Unlock()
+
+	// Expire a few minutes early so we don't hand out nearly-dead certs.
+	expiresAt := notAfter
+	if !notAfter.IsZero() {
+		const margin = 5 * time.Minute
+		if notAfter.After(time.Now().Add(margin)) {
+			expiresAt = notAfter.Add(-margin)
+		}
+	}
+
+	if el, ok := c.entries[host]; ok {
+		c.ll.MoveToFront(el)
+		el.Value = &leafCacheEntry{
+			host:      host,
+			cert:      cert,
+			notAfter:  notAfter,
+			expiresAt: expiresAt,
+		}
+		return
+	}
+
+	for c.ll.Len() >= c.max {
+		c.evictOldest()
+	}
+	el := c.ll.PushFront(&leafCacheEntry{
+		host:      host,
+		cert:      cert,
+		notAfter:  notAfter,
+		expiresAt: expiresAt,
+	})
+	c.entries[host] = el
+}
+
+// Len returns the number of entries currently in the cache.
+func (c *LeafCache) Len() int {
+	if c == nil {
+		return 0
+	}
+	c.mu.Lock()
+	defer c.mu.Unlock()
+	return c.ll.Len()
+}
+
+// Clear removes all entries (e.g. after CA rotation).
+func (c *LeafCache) Clear() {
+	if c == nil {
+		return
+	}
+	c.mu.Lock()
+	defer c.mu.Unlock()
+	c.ll.Init()
+	c.entries = make(map[string]*list.Element, c.max)
+}
+
+func (c *LeafCache) evictOldest() {
+	el := c.ll.Back()
+	if el == nil {
+		return
+	}
+	c.removeElement(el)
+}
+
+func (c *LeafCache) removeElement(el *list.Element) {
+	ent := el.Value.(*leafCacheEntry)
+	delete(c.entries, ent.host)
+	c.ll.Remove(el)
+}
diff --git a/internal/certs/leaf_cache_test.go b/internal/certs/leaf_cache_test.go
new file mode 100644
index 0000000..3a4815e
--- /dev/null
+++ b/internal/certs/leaf_cache_test.go
@@ -0,0 +1,123 @@
+package certs
+
+import (
+	"crypto/tls"
+	"fmt"
+	"testing"
+	"time"
+)
+
+func TestLeafCacheGetPut(t *testing.T) {
+	c := NewLeafCache(4)
+	if c.Len() != 0 {
+		t.Fatalf("Len = %d, want 0", c.Len())
+	}
+
+	cert := &tls.Certificate{}
+	notAfter := time.Now().Add(48 * time.Hour)
+	c.Put("a.example", cert, notAfter)
+
+	got, ok := c.Get("a.example")
+	if !ok || got != cert {
+		t.Fatalf("Get hit = (%v, %v), want cert", got, ok)
+	}
+	if _, ok := c.Get("missing.example"); ok {
+		t.Fatal("Get miss expected false")
+	}
+}
+
+func TestLeafCacheLRUEviction(t *testing.T) {
+	const max = 3
+	c := NewLeafCache(max)
+
+	notAfter := time.Now().Add(time.Hour)
+	for i := 0; i < max; i++ {
+		host := fmt.Sprintf("h%d.example", i)
+		c.Put(host, &tls.Certificate{}, notAfter)
+	}
+	if c.Len() != max {
+		t.Fatalf("Len = %d, want %d", c.Len(), max)
+	}
+
+	// Access h0 so h1 is the oldest after we use h0.
+	if _, ok := c.Get("h0.example"); !ok {
+		t.Fatal("h0 missing")
+	}
+
+	// Insert h3 ΓåÆ should evict least recently used (h1).
+	c.Put("h3.example", &tls.Certificate{}, notAfter)
+	if c.Len() != max {
+		t.Fatalf("Len after put = %d, want %d", c.Len(), max)
+	}
+	if _, ok := c.Get("h1.example"); ok {
+		t.Fatal("h1 should have been evicted")
+	}
+	for _, host := range []string{"h0.example", "h2.example", "h3.example"} {
+		if _, ok := c.Get(host); !ok {
+			t.Fatalf("%s should remain", host)
+		}
+	}
+}
+
+func TestLeafCacheExpired(t *testing.T) {
+	c := NewLeafCache(8)
+	// Already expired
+	c.Put("old.example", &tls.Certificate{}, time.Now().Add(-time.Minute))
+	if _, ok := c.Get("old.example"); ok {
+		t.Fatal("expired entry should miss")
+	}
+	if c.Len() != 0 {
+		t.Fatalf("expired entry should be removed, Len=%d", c.Len())
+	}
+}
+
+func TestLeafCacheClear(t *testing.T) {
+	c := NewLeafCache(8)
+	c.Put("a.example", &tls.Certificate{}, time.Now().Add(time.Hour))
+	c.Put("b.example", &tls.Certificate{}, time.Now().Add(time.Hour))
+	c.Clear()
+	if c.Len() != 0 {
+		t.Fatalf("Len after Clear = %d", c.Len())
+	}
+	if _, ok := c.Get("a.example"); ok {
+		t.Fatal("Get after Clear should miss")
+	}
+}
+
+func TestLeafCacheDefaultSize(t *testing.T) {
+	c := NewLeafCache(0)
+	if c.max != DefaultLeafCacheSize {
+		t.Fatalf("max = %d, want %d", c.max, DefaultLeafCacheSize)
+	}
+}
+
+func TestLeafCacheNilSafe(t *testing.T) {
+	var c *LeafCache
+	if _, ok := c.Get("x"); ok {
+		t.Fatal("nil Get should miss")
+	}
+	c.Put("x", &tls.Certificate{}, time.Now().Add(time.Hour))
+	c.Clear()
+	if c.Len() != 0 {
+		t.Fatal("nil Len should be 0")
+	}
+}
+
+func TestLeafCacheUpdateMovesToFront(t *testing.T) {
+	c := NewLeafCache(2)
+	notAfter := time.Now().Add(time.Hour)
+	c.Put("a", &tls.Certificate{}, notAfter)
+	c.Put("b", &tls.Certificate{}, notAfter)
+	// Update a (should become MRU); inserting c should evict b.
+	c.Put("a", &tls.Certificate{}, notAfter)
+	c.Put("c", &tls.Certificate{}, notAfter)
+	if _, ok := c.Get("b"); ok {
+		t.Fatal("b should be evicted")
+	}
+	if _, ok := c.Get("a"); !ok {
+		t.Fatal("a should remain")
+	}
+	if _, ok := c.Get("c"); !ok {
+		t.Fatal("c should remain")
+	}
+}
diff --git a/internal/store/certificates.go b/internal/store/certificates.go
new file mode 100644
index 0000000..07398f6
--- /dev/null
+++ b/internal/store/certificates.go
@@ -0,0 +1,182 @@
+package store
+
+import (
+	"context"
+	"errors"
+	"fmt"
+	"time"
+
+	"github.com/google/uuid"
+	"github.com/jackc/pgx/v5"
+)
+
+// Certificate kinds stored in certificates.kind.
+const (
+	CertKindSelfSignedCA = "self_signed_ca"
+)
+
+// Certificate is a row from the certificates table.
+// KeyPEMEncrypted holds the AES-GCM box of the private key PEM; never expose via API.
+type Certificate struct {
+	ID                uuid.UUID `json:"id"`
+	Name              string    `json:"name"`
+	Kind              string    `json:"kind"`
+	CertPEM           string    `json:"cert_pem"`
+	KeyPEMEncrypted   []byte    `json:"-"`
+	FingerprintSHA256 string    `json:"fingerprint_sha256"`
+	NotBefore         time.Time `json:"not_before"`
+	NotAfter          time.Time `json:"not_after"`
+	IsActive          bool      `json:"is_active"`
+	CreatedAt         time.Time `json:"created_at"`
+}
+
+// InsertActiveCertificate deactivates any existing active CA of the same kind,
+// then inserts c as the active certificate. Returns the stored row (with id/created_at).
+func (s *Store) InsertActiveCertificate(ctx context.Context, c Certificate) (Certificate, error) {
+	if c.Name == "" {
+		return Certificate{}, fmt.Errorf("certificate name is required")
+	}
+	if c.Kind == "" {
+		c.Kind = CertKindSelfSignedCA
+	}
+	if c.Kind != CertKindSelfSignedCA {
+		return Certificate{}, fmt.Errorf("invalid certificate kind %q", c.Kind)
+	}
+	if c.CertPEM == "" {
+		return Certificate{}, fmt.Errorf("cert_pem is required")
+	}
+	if len(c.KeyPEMEncrypted) == 0 {
+		return Certificate{}, fmt.Errorf("key_pem_encrypted is required")
+	}
+	if c.FingerprintSHA256 == "" {
+		return Certificate{}, fmt.Errorf("fingerprint_sha256 is required")
+	}
+	if c.NotBefore.IsZero() || c.NotAfter.IsZero() {
+		return Certificate{}, fmt.Errorf("not_before and not_after are required")
+	}
+	if !c.NotAfter.After(c.NotBefore) {
+		return Certificate{}, fmt.Errorf("not_after must be after not_before")
+	}
+
+	tx, err := s.pool.Begin(ctx)
+	if err != nil {
+		return Certificate{}, fmt.Errorf("begin tx: %w", err)
+	}
+	defer tx.Rollback(ctx) //nolint:errcheck
+
+	// Clear active flag so the partial unique index allows the new active row.
+	const deactivate = `
+UPDATE certificates
+SET is_active = FALSE
+WHERE is_active = TRUE AND kind = $1
+`
+	if _, err := tx.Exec(ctx, deactivate, c.Kind); err != nil {
+		return Certificate{}, fmt.Errorf("deactivate certificates: %w", err)
+	}
+
+	const insert = `
+INSERT INTO certificates (
+    name, kind, cert_pem, key_pem_encrypted, fingerprint_sha256,
+    not_before, not_after, is_active
+) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
+RETURNING id, name, kind, cert_pem, key_pem_encrypted, fingerprint_sha256,
+          not_before, not_after, is_active, created_at
+`
+	var out Certificate
+	err = tx.QueryRow(ctx, insert,
+		c.Name,
+		c.Kind,
+		c.CertPEM,
+		c.KeyPEMEncrypted,
+		c.FingerprintSHA256,
+		c.NotBefore.UTC(),
+		c.NotAfter.UTC(),
+	).Scan(
+		&out.ID,
+		&out.Name,
+		&out.Kind,
+		&out.CertPEM,
+		&out.KeyPEMEncrypted,
+		&out.FingerprintSHA256,
+		&out.NotBefore,
+		&out.NotAfter,
+		&out.IsActive,
+		&out.CreatedAt,
+	)
+	if err != nil {
+		return Certificate{}, fmt.Errorf("insert certificate: %w", err)
+	}
+
+	if err := tx.Commit(ctx); err != nil {
+		return Certificate{}, fmt.Errorf("commit certificate: %w", err)
+	}
+	return out, nil
+}
+
+// GetActiveCertificate returns the active certificate of the given kind.
+// ok is false when none is active (no error).
+func (s *Store) GetActiveCertificate(ctx context.Context, kind string) (Certificate, bool, error) {
+	if kind == "" {
+		kind = CertKindSelfSignedCA
+	}
+	const q = `
+SELECT id, name, kind, cert_pem, key_pem_encrypted, fingerprint_sha256,
+       not_before, not_after, is_active, created_at
+FROM certificates
+WHERE is_active = TRUE AND kind = $1
+LIMIT 1
+`
+	var out Certificate
+	err := s.pool.QueryRow(ctx, q, kind).Scan(
+		&out.ID,
+		&out.Name,
+		&out.Kind,
+		&out.CertPEM,
+		&out.KeyPEMEncrypted,
+		&out.FingerprintSHA256,
+		&out.NotBefore,
+		&out.NotAfter,
+		&out.IsActive,
+		&out.CreatedAt,
+	)
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return Certificate{}, false, nil
+		}
+		return Certificate{}, false, fmt.Errorf("get active certificate: %w", err)
+	}
+	return out, true, nil
+}
+
+// GetCertificateByID returns a certificate by id (includes encrypted key material for server use).
+func (s *Store) GetCertificateByID(ctx context.Context, id uuid.UUID) (Certificate, error) {
+	if id == uuid.Nil {
+		return Certificate{}, fmt.Errorf("certificate id is required")
+	}
+	const q = `
+SELECT id, name, kind, cert_pem, key_pem_encrypted, fingerprint_sha256,
+       not_before, not_after, is_active, created_at
+FROM certificates
+WHERE id = $1
+`
+	var out Certificate
+	err := s.pool.QueryRow(ctx, q, id).Scan(
+		&out.ID,
+		&out.Name,
+		&out.Kind,
+		&out.CertPEM,
+		&out.KeyPEMEncrypted,
+		&out.FingerprintSHA256,
+		&out.NotBefore,
+		&out.NotAfter,
+		&out.IsActive,
+		&out.CreatedAt,
+	)
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return Certificate{}, fmt.Errorf("certificate %s: %w", id, err)
+		}
+		return Certificate{}, fmt.Errorf("get certificate: %w", err)
+	}
+	return out, nil
+}
