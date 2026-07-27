// Package auth provides password hashing, admin session tokens, and proxy IP auth cache.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP-aligned interactive login defaults).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB → 64 MiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns a PHC-formatted argon2id hash of password.
// Empty passwords are rejected.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}

	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64Salt, b64Hash,
	)
	return encoded, nil
}

// CheckPassword reports whether password matches a PHC argon2id hash.
// Invalid or unsupported hashes return false (never panics).
func CheckPassword(hash, password string) bool {
	if hash == "" || password == "" {
		return false
	}

	salt, expected, time, memory, threads, keyLen, err := parseArgon2idHash(hash)
	if err != nil {
		return false
	}

	got := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
	if len(got) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare(got, expected) == 1
}

func parseArgon2idHash(encoded string) (salt, hash []byte, time, memory uint32, threads uint8, keyLen uint32, err error) {
	// $argon2id$v=19$m=65536,t=3,p=2$salt$hash
	parts := strings.Split(encoded, "$")
	// Split yields leading empty element before first $.
	if len(parts) != 6 {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid hash format")
	}
	if parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("unsupported algorithm %q", parts[1])
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("parse version: %w", err)
	}
	if version != argon2.Version {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("unsupported argon2 version %d", version)
	}

	var t, m uint32
	var p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("parse params: %w", err)
	}
	if t == 0 || m == 0 || p == 0 || p > 255 {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid argon2 params")
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		// Some encoders pad; accept standard encoding too.
		salt, err = base64.StdEncoding.DecodeString(parts[4])
		if err != nil {
			return nil, nil, 0, 0, 0, 0, fmt.Errorf("decode salt: %w", err)
		}
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		hash, err = base64.StdEncoding.DecodeString(parts[5])
		if err != nil {
			return nil, nil, 0, 0, 0, 0, fmt.Errorf("decode hash: %w", err)
		}
	}
	if len(salt) == 0 || len(hash) == 0 {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("empty salt or hash")
	}

	return salt, hash, t, m, uint8(p), uint32(len(hash)), nil
}
