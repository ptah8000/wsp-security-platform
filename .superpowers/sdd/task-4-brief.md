### Task 4: Certificate CA + encrypted key storage + leaf cache

**Files:**
- Create: `internal/certs/crypto_box.go`, `ca.go`, `leaf_cache.go`
- Test: `internal/certs/ca_test.go`, `leaf_cache_test.go`

**Interfaces:**
```go
type Provider struct { store *store.Store; dataKey []byte; cache *LeafCache }
func NewProvider(store *store.Store, dataKey string) (*Provider, error)
func (p *Provider) GenerateSelfSignedCA(ctx context.Context, name string) (CertMeta, error)
func (p *Provider) ActiveCA(ctx context.Context) (certPEM []byte, ok bool, err error)
func (p *Provider) SignHost(host string) (*tls.Certificate, error) // uses in-memory active CA key
```

- [ ] **Step 1: AES-GCM box for CA private key** using key derived from `WSP_DATA_KEY` (require min 16 chars; hash with SHA-256 to 32 bytes)

- [ ] **Step 2: Generate CA RSA 4096 or ECDSA P-256** (prefer ECDSA P-256 for perf) valid 10 years; store PEM cert + encrypted key

- [ ] **Step 3: Leaf cache LRU** max 1024 hosts; generate leaf with SAN DNS=host, 48h validity

- [ ] **Step 4: Unit test** generate CA → SignHost(`example.com`) → verify chain

- [ ] **Step 5: Commit** `feat: self-signed CA generation and MITM leaf cache`

---
