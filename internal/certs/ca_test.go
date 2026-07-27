package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

const testDataKey = "test-data-key-16b" // exactly 16 chars minimum

func TestDeriveKeyMinLength(t *testing.T) {
	if _, err := DeriveKey("short"); err == nil {
		t.Fatal("DeriveKey(short) expected error")
	}
	key, err := DeriveKey(testDataKey)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key len = %d, want 32", len(key))
	}
	// Deterministic.
	key2, err := DeriveKey(testDataKey)
	if err != nil {
		t.Fatalf("DeriveKey #2: %v", err)
	}
	if sha256.Sum256(key) != sha256.Sum256(key2) {
		t.Fatal("DeriveKey not deterministic")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := DeriveKey(testDataKey)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	plain := []byte("-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----")
	box, err := Seal(key, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(box) <= len(plain) {
		t.Fatalf("box should be longer than plaintext (nonce+tag), got %d vs %d", len(box), len(plain))
	}
	out, err := Open(key, box)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(out) != string(plain) {
		t.Fatalf("Open = %q, want %q", out, plain)
	}
	// Wrong key fails.
	other, _ := DeriveKey("other-data-key!!")
	if _, err := Open(other, box); err == nil {
		t.Fatal("Open with wrong key expected error")
	}
	// Seal produces unique nonces.
	box2, err := Seal(key, plain)
	if err != nil {
		t.Fatalf("Seal #2: %v", err)
	}
	if string(box) == string(box2) {
		t.Fatal("Seal should use random nonces")
	}
}

func TestNewProviderRejectsShortKey(t *testing.T) {
	if _, err := NewProvider(nil, "tooshort"); err == nil {
		t.Fatal("NewProvider with short key expected error")
	}
}

func TestGenerateCA_SignHost_VerifyChain(t *testing.T) {
	p, err := NewProvider(nil, testDataKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx := context.Background()
	meta, err := p.GenerateSelfSignedCA(ctx, "WSP Test CA")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	if meta.Name != "WSP Test CA" {
		t.Fatalf("meta.Name = %q", meta.Name)
	}
	if meta.FingerprintSHA256 == "" {
		t.Fatal("empty fingerprint")
	}
	if !meta.IsActive {
		t.Fatal("meta.IsActive = false")
	}
	// ~10 years
	if meta.NotAfter.Sub(meta.NotBefore) < 9*365*24*time.Hour {
		t.Fatalf("CA validity too short: %v", meta.NotAfter.Sub(meta.NotBefore))
	}

	certPEM, ok, err := p.ActiveCA(ctx)
	if err != nil {
		t.Fatalf("ActiveCA: %v", err)
	}
	if !ok || len(certPEM) == 0 {
		t.Fatal("ActiveCA returned empty")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("ActiveCA not valid PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	if !caCert.IsCA {
		t.Fatal("CA cert IsCA = false")
	}
	// Prefer ECDSA P-256
	if _, ok := caCert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("CA public key type %T, want *ecdsa.PublicKey", caCert.PublicKey)
	}
	if pub, ok := caCert.PublicKey.(*ecdsa.PublicKey); ok {
		if pub.Curve.Params().Name != "P-256" {
			t.Fatalf("CA curve = %s, want P-256", pub.Curve.Params().Name)
		}
	}

	// Sign leaf for example.com
	leafTLS, err := p.SignHost("example.com")
	if err != nil {
		t.Fatalf("SignHost: %v", err)
	}
	if leafTLS == nil || leafTLS.Leaf == nil {
		t.Fatal("SignHost returned nil leaf")
	}
	if len(leafTLS.Certificate) < 1 {
		t.Fatal("leaf Certificate DER missing")
	}

	leaf := leafTLS.Leaf
	if err := leaf.VerifyHostname("example.com"); err != nil {
		t.Fatalf("VerifyHostname: %v", err)
	}
	// SAN DNS
	foundDNS := false
	for _, d := range leaf.DNSNames {
		if d == "example.com" {
			foundDNS = true
			break
		}
	}
	if !foundDNS {
		t.Fatalf("DNSNames = %v, want example.com", leaf.DNSNames)
	}

	// ~48h validity
	validFor := leaf.NotAfter.Sub(leaf.NotBefore)
	if validFor < 40*time.Hour || validFor > 55*time.Hour {
		t.Fatalf("leaf validity = %v, want ~48h", validFor)
	}

	// Verify chain: leaf → CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   roots,
		// Leaf is for server auth.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// If chain includes intermediate (CA DER as second), use Intermediates.
	inter := x509.NewCertPool()
	if len(leafTLS.Certificate) > 1 {
		if ic, err := x509.ParseCertificate(leafTLS.Certificate[1]); err == nil {
			inter.AddCert(ic)
		}
	}
	opts.Intermediates = inter

	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("chain verify: %v", err)
	}

	// Cache hit returns same material
	leaf2, err := p.SignHost("example.com")
	if err != nil {
		t.Fatalf("SignHost cache: %v", err)
	}
	if leaf2.Leaf.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("cache miss regenerated leaf serial")
	}

	// Different host gets different cert
	other, err := p.SignHost("other.example")
	if err != nil {
		t.Fatalf("SignHost other: %v", err)
	}
	if other.Leaf.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
		t.Fatal("different hosts share serial")
	}
	if err := other.Leaf.VerifyHostname("other.example"); err != nil {
		t.Fatalf("other VerifyHostname: %v", err)
	}
}

func TestSignHostRequiresCA(t *testing.T) {
	p, err := NewProvider(nil, testDataKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if _, err := p.SignHost("example.com"); err == nil {
		t.Fatal("SignHost without CA expected error")
	}
}

func TestSignHostEmptyHost(t *testing.T) {
	p, err := NewProvider(nil, testDataKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if _, err := p.GenerateSelfSignedCA(context.Background(), "CA"); err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	if _, err := p.SignHost(""); err == nil {
		t.Fatal("SignHost empty expected error")
	}
}

func TestSignHostStripsPort(t *testing.T) {
	p, err := NewProvider(nil, testDataKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if _, err := p.GenerateSelfSignedCA(context.Background(), "CA"); err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	cert, err := p.SignHost("example.com:443")
	if err != nil {
		t.Fatalf("SignHost: %v", err)
	}
	if err := cert.Leaf.VerifyHostname("example.com"); err != nil {
		t.Fatalf("VerifyHostname: %v", err)
	}
}

func TestSignHostIP(t *testing.T) {
	p, err := NewProvider(nil, testDataKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if _, err := p.GenerateSelfSignedCA(context.Background(), "CA"); err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	cert, err := p.SignHost("127.0.0.1")
	if err != nil {
		t.Fatalf("SignHost: %v", err)
	}
	if err := cert.Leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("VerifyHostname IP: %v", err)
	}
	if len(cert.Leaf.IPAddresses) == 0 {
		t.Fatal("expected IP SAN")
	}
}

func TestCARotationClearsLeafCache(t *testing.T) {
	p, err := NewProvider(nil, testDataKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	ctx := context.Background()
	if _, err := p.GenerateSelfSignedCA(ctx, "CA1"); err != nil {
		t.Fatalf("CA1: %v", err)
	}
	leaf1, err := p.SignHost("example.com")
	if err != nil {
		t.Fatalf("SignHost: %v", err)
	}
	if _, err := p.GenerateSelfSignedCA(ctx, "CA2"); err != nil {
		t.Fatalf("CA2: %v", err)
	}
	leaf2, err := p.SignHost("example.com")
	if err != nil {
		t.Fatalf("SignHost after rotate: %v", err)
	}
	if leaf1.Leaf.SerialNumber.Cmp(leaf2.Leaf.SerialNumber) == 0 {
		t.Fatal("leaf serial unchanged after CA rotation (cache not cleared?)")
	}
	// New leaf must chain to new CA
	certPEM, ok, err := p.ActiveCA(ctx)
	if err != nil || !ok {
		t.Fatalf("ActiveCA: ok=%v err=%v", ok, err)
	}
	block, _ := pem.Decode(certPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf2.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "example.com",
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("verify under new CA: %v", err)
	}
}
