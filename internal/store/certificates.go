package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Certificate kinds stored in certificates.kind.
const (
	CertKindSelfSignedCA = "self_signed_ca"
)

// Certificate is a row from the certificates table.
// KeyPEMEncrypted holds the AES-GCM box of the private key PEM; never expose via API.
type Certificate struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	Kind              string    `json:"kind"`
	CertPEM           string    `json:"cert_pem"`
	KeyPEMEncrypted   []byte    `json:"-"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	IsActive          bool      `json:"is_active"`
	CreatedAt         time.Time `json:"created_at"`
}

// InsertActiveCertificate deactivates any existing active CA of the same kind,
// then inserts c as the active certificate. Returns the stored row (with id/created_at).
func (s *Store) InsertActiveCertificate(ctx context.Context, c Certificate) (Certificate, error) {
	if c.Name == "" {
		return Certificate{}, fmt.Errorf("certificate name is required")
	}
	if c.Kind == "" {
		c.Kind = CertKindSelfSignedCA
	}
	if c.Kind != CertKindSelfSignedCA {
		return Certificate{}, fmt.Errorf("invalid certificate kind %q", c.Kind)
	}
	if c.CertPEM == "" {
		return Certificate{}, fmt.Errorf("cert_pem is required")
	}
	if len(c.KeyPEMEncrypted) == 0 {
		return Certificate{}, fmt.Errorf("key_pem_encrypted is required")
	}
	if c.FingerprintSHA256 == "" {
		return Certificate{}, fmt.Errorf("fingerprint_sha256 is required")
	}
	if c.NotBefore.IsZero() || c.NotAfter.IsZero() {
		return Certificate{}, fmt.Errorf("not_before and not_after are required")
	}
	if !c.NotAfter.After(c.NotBefore) {
		return Certificate{}, fmt.Errorf("not_after must be after not_before")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Certificate{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Clear active flag so the partial unique index allows the new active row.
	const deactivate = `
UPDATE certificates
SET is_active = FALSE
WHERE is_active = TRUE AND kind = $1
`
	if _, err := tx.Exec(ctx, deactivate, c.Kind); err != nil {
		return Certificate{}, fmt.Errorf("deactivate certificates: %w", err)
	}

	const insert = `
INSERT INTO certificates (
    name, kind, cert_pem, key_pem_encrypted, fingerprint_sha256,
    not_before, not_after, is_active
) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
RETURNING id, name, kind, cert_pem, key_pem_encrypted, fingerprint_sha256,
          not_before, not_after, is_active, created_at
`
	var out Certificate
	err = tx.QueryRow(ctx, insert,
		c.Name,
		c.Kind,
		c.CertPEM,
		c.KeyPEMEncrypted,
		c.FingerprintSHA256,
		c.NotBefore.UTC(),
		c.NotAfter.UTC(),
	).Scan(
		&out.ID,
		&out.Name,
		&out.Kind,
		&out.CertPEM,
		&out.KeyPEMEncrypted,
		&out.FingerprintSHA256,
		&out.NotBefore,
		&out.NotAfter,
		&out.IsActive,
		&out.CreatedAt,
	)
	if err != nil {
		return Certificate{}, fmt.Errorf("insert certificate: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, fmt.Errorf("commit certificate: %w", err)
	}
	return out, nil
}

// GetActiveCertificate returns the active certificate of the given kind.
// ok is false when none is active (no error).
func (s *Store) GetActiveCertificate(ctx context.Context, kind string) (Certificate, bool, error) {
	if kind == "" {
		kind = CertKindSelfSignedCA
	}
	const q = `
SELECT id, name, kind, cert_pem, key_pem_encrypted, fingerprint_sha256,
       not_before, not_after, is_active, created_at
FROM certificates
WHERE is_active = TRUE AND kind = $1
LIMIT 1
`
	var out Certificate
	err := s.pool.QueryRow(ctx, q, kind).Scan(
		&out.ID,
		&out.Name,
		&out.Kind,
		&out.CertPEM,
		&out.KeyPEMEncrypted,
		&out.FingerprintSHA256,
		&out.NotBefore,
		&out.NotAfter,
		&out.IsActive,
		&out.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Certificate{}, false, nil
		}
		return Certificate{}, false, fmt.Errorf("get active certificate: %w", err)
	}
	return out, true, nil
}

// GetCertificateByID returns a certificate by id (includes encrypted key material for server use).
func (s *Store) GetCertificateByID(ctx context.Context, id uuid.UUID) (Certificate, error) {
	if id == uuid.Nil {
		return Certificate{}, fmt.Errorf("certificate id is required")
	}
	const q = `
SELECT id, name, kind, cert_pem, key_pem_encrypted, fingerprint_sha256,
       not_before, not_after, is_active, created_at
FROM certificates
WHERE id = $1
`
	var out Certificate
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&out.ID,
		&out.Name,
		&out.Kind,
		&out.CertPEM,
		&out.KeyPEMEncrypted,
		&out.FingerprintSHA256,
		&out.NotBefore,
		&out.NotAfter,
		&out.IsActive,
		&out.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Certificate{}, fmt.Errorf("certificate %s: %w", id, err)
		}
		return Certificate{}, fmt.Errorf("get certificate: %w", err)
	}
	return out, nil
}

// CertificateMeta is public certificate metadata (never includes private key material).
type CertificateMeta struct {
	ID                uuid.UUID `json:"id"`
	Name              string    `json:"name"`
	Kind              string    `json:"kind"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	IsActive          bool      `json:"is_active"`
	CreatedAt         time.Time `json:"created_at"`
}

// ListCertificates returns public metadata for all certificates (no keys, no PEM by default).
func (s *Store) ListCertificates(ctx context.Context) ([]CertificateMeta, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("store is nil")
	}
	const q = `
SELECT id, name, kind, fingerprint_sha256, not_before, not_after, is_active, created_at
FROM certificates
ORDER BY is_active DESC, created_at DESC, id ASC
`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var out []CertificateMeta
	for rows.Next() {
		var c CertificateMeta
		if err := rows.Scan(
			&c.ID, &c.Name, &c.Kind, &c.FingerprintSHA256,
			&c.NotBefore, &c.NotAfter, &c.IsActive, &c.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	if out == nil {
		out = []CertificateMeta{}
	}
	return out, nil
}

// GetCertificatePublicPEM returns only the public cert_pem for id (never the private key).
func (s *Store) GetCertificatePublicPEM(ctx context.Context, id uuid.UUID) (certPEM string, meta CertificateMeta, err error) {
	if s == nil || s.pool == nil {
		return "", CertificateMeta{}, fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return "", CertificateMeta{}, fmt.Errorf("certificate id is required")
	}
	const q = `
SELECT id, name, kind, cert_pem, fingerprint_sha256, not_before, not_after, is_active, created_at
FROM certificates
WHERE id = $1
`
	err = s.pool.QueryRow(ctx, q, id).Scan(
		&meta.ID, &meta.Name, &meta.Kind, &certPEM,
		&meta.FingerprintSHA256, &meta.NotBefore, &meta.NotAfter, &meta.IsActive, &meta.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", CertificateMeta{}, fmt.Errorf("certificate %s: %w", id, err)
		}
		return "", CertificateMeta{}, fmt.Errorf("get certificate pem: %w", err)
	}
	return certPEM, meta, nil
}
