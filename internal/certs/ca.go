package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/store"
)

// CA and leaf validity defaults.
const (
	// DefaultCAValidity is how long a generated self-signed CA remains valid.
	DefaultCAValidity = 10 * 365 * 24 * time.Hour // ~10 years
	// DefaultLeafValidity is how long MITM leaf certificates remain valid.
	DefaultLeafValidity = 48 * time.Hour
)

// CertMeta is public metadata for a stored CA certificate (no private key).
type CertMeta struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	Kind              string    `json:"kind"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	IsActive          bool      `json:"is_active"`
	CreatedAt         time.Time `json:"created_at"`
}

// Provider generates and stores a self-signed CA, and signs short-lived leaf
// certificates for MITM. The active CA private key is held in memory after
// generation or first load/decrypt from the store.
type Provider struct {
	store   *store.Store
	dataKey []byte
	cache   *LeafCache

	mu        sync.RWMutex
	caCert    *x509.Certificate
	caKey     crypto.Signer
	caCertPEM []byte
}

// NewProvider builds a certs.Provider. dataKey is the WSP_DATA_KEY string
// (min 16 chars); it is hashed to a 32-byte AES key for encrypting CA private keys.
// store may be nil for in-memory-only unit tests (GenerateSelfSignedCA will not persist).
func NewProvider(s *store.Store, dataKey string) (*Provider, error) {
	key, err := DeriveKey(dataKey)
	if err != nil {
		return nil, err
	}
	return &Provider{
		store:   s,
		dataKey: key,
		cache:   NewLeafCache(DefaultLeafCacheSize),
	}, nil
}

// GenerateSelfSignedCA creates an ECDSA P-256 self-signed CA (≈10y), encrypts the
// private key with the data key, stores it as the active CA when a store is configured,
// and keeps the CA key in memory for SignHost.
func (p *Provider) GenerateSelfSignedCA(ctx context.Context, name string) (CertMeta, error) {
	if p == nil {
		return CertMeta{}, errors.New("provider is nil")
	}
	if name == "" {
		return CertMeta{}, errors.New("CA name is required")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CertMeta{}, fmt.Errorf("generate CA key: %w", err)
	}

	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Hour) // clock skew
	notAfter := now.Add(DefaultCAValidity)

	serial, err := randomSerial()
	if err != nil {
		return CertMeta{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"WSP"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return CertMeta{}, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertMeta{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return CertMeta{}, fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	encKey, err := Seal(p.dataKey, keyPEM)
	if err != nil {
		return CertMeta{}, fmt.Errorf("encrypt CA key: %w", err)
	}

	fp := sha256.Sum256(der)
	fpHex := hex.EncodeToString(fp[:])

	meta := CertMeta{
		Name:              name,
		Kind:              store.CertKindSelfSignedCA,
		FingerprintSHA256: fpHex,
		NotBefore:         caCert.NotBefore,
		NotAfter:          caCert.NotAfter,
		IsActive:          true,
	}

	if p.store != nil {
		row, err := p.store.InsertActiveCertificate(ctx, store.Certificate{
			Name:              name,
			Kind:              store.CertKindSelfSignedCA,
			CertPEM:           string(certPEM),
			KeyPEMEncrypted:   encKey,
			FingerprintSHA256: fpHex,
			NotBefore:         caCert.NotBefore,
			NotAfter:          caCert.NotAfter,
		})
		if err != nil {
			return CertMeta{}, err
		}
		meta.ID = row.ID
		meta.CreatedAt = row.CreatedAt
		meta.IsActive = row.IsActive
	}

	// Install active CA in memory and drop leaves signed by any previous CA.
	p.mu.Lock()
	p.caCert = caCert
	p.caKey = priv
	p.caCertPEM = certPEM
	p.mu.Unlock()
	p.cache.Clear()

	return meta, nil
}

// ActiveCA returns the PEM-encoded public certificate of the active CA.
// ok is false when no CA is loaded or stored.
func (p *Provider) ActiveCA(ctx context.Context) (certPEM []byte, ok bool, err error) {
	if p == nil {
		return nil, false, errors.New("provider is nil")
	}

	p.mu.RLock()
	if len(p.caCertPEM) > 0 {
		out := append([]byte(nil), p.caCertPEM...)
		p.mu.RUnlock()
		return out, true, nil
	}
	p.mu.RUnlock()

	if err := p.loadActiveCA(ctx); err != nil {
		return nil, false, err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.caCertPEM) == 0 {
		return nil, false, nil
	}
	return append([]byte(nil), p.caCertPEM...), true, nil
}

// SignHost returns a leaf TLS certificate for host (SAN DNS or IP), signed by
// the active CA. Results are cached in an LRU of size DefaultLeafCacheSize.
// The active CA key must be available in memory or loadable from the store.
func (p *Provider) SignHost(host string) (*tls.Certificate, error) {
	if p == nil {
		return nil, errors.New("provider is nil")
	}
	host = normalizeHost(host)
	if host == "" {
		return nil, errors.New("host is required")
	}

	if cert, ok := p.cache.Get(host); ok {
		return cert, nil
	}

	if err := p.ensureCALoaded(context.Background()); err != nil {
		return nil, err
	}

	p.mu.RLock()
	caCert := p.caCert
	caKey := p.caKey
	caCertPEM := p.caCertPEM
	p.mu.RUnlock()
	if caCert == nil || caKey == nil {
		return nil, errors.New("no active CA")
	}

	leaf, notAfter, err := signLeaf(caCert, caKey, host)
	if err != nil {
		return nil, err
	}

	// tls.Certificate with leaf + CA for chain presentation.
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{leaf.Certificate[0], caCert.Raw},
		PrivateKey:  leaf.PrivateKey,
		Leaf:        leaf.Leaf,
	}
	// Keep caCertPEM referenced so callers who only have leaf still have chain DER.
	_ = caCertPEM

	p.cache.Put(host, tlsCert, notAfter)
	return tlsCert, nil
}

// ensureCALoaded loads and decrypts the active CA into memory if not already present.
func (p *Provider) ensureCALoaded(ctx context.Context) error {
	p.mu.RLock()
	ready := p.caCert != nil && p.caKey != nil
	p.mu.RUnlock()
	if ready {
		return nil
	}
	return p.loadActiveCA(ctx)
}

// loadActiveCA fetches the active CA from the store, decrypts the key, and installs it.
func (p *Provider) loadActiveCA(ctx context.Context) error {
	if p.store == nil {
		return nil // in-memory-only mode; GenerateSelfSignedCA must have been called
	}

	row, ok, err := p.store.GetActiveCertificate(ctx, store.CertKindSelfSignedCA)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	keyPEM, err := Open(p.dataKey, row.KeyPEMEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt CA key: %w", err)
	}

	caCert, caKey, err := parseCAMaterial([]byte(row.CertPEM), keyPEM)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.caCert = caCert
	p.caKey = caKey
	p.caCertPEM = []byte(row.CertPEM)
	p.mu.Unlock()
	return nil
}

func parseCAMaterial(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("invalid CA key PEM")
	}

	var signer crypto.Signer
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse EC private key: %w", err)
		}
		signer = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, nil, errors.New("CA key is not a signer")
		}
		signer = s
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse RSA private key: %w", err)
		}
		signer = k
	default:
		return nil, nil, fmt.Errorf("unsupported CA key PEM type %q", keyBlock.Type)
	}

	return caCert, signer, nil
}

func signLeaf(caCert *x509.Certificate, caKey crypto.Signer, host string) (*tls.Certificate, time.Time, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate leaf key: %w", err)
	}

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(DefaultLeafValidity)

	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("create leaf certificate: %w", err)
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse leaf certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leafCert,
	}, notAfter, nil
}

func randomSerial() (*big.Int, error) {
	// 128-bit positive serial.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	// Avoid serial 0.
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n, nil
}

// normalizeHost strips a trailing port if present (host:port → host).
// IPv6 bracket form [addr]:port is supported.
func normalizeHost(host string) string {
	if host == "" {
		return ""
	}
	// host:port or [ipv6]:port
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	// Bare IPv6 without brackets — leave as-is for ParseIP in signLeaf.
	return host
}
