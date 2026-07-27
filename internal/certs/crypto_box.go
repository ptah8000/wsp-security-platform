// Package certs provides self-signed CA generation, encrypted key storage,
// and on-demand MITM leaf certificates with an in-memory LRU cache.
package certs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// MinDataKeyLen is the minimum accepted length of WSP_DATA_KEY (UTF-8 bytes).
const MinDataKeyLen = 16

// DeriveKey turns a user-supplied data key (WSP_DATA_KEY) into a 32-byte AES key
// via SHA-256. Requires at least MinDataKeyLen characters.
func DeriveKey(dataKey string) ([]byte, error) {
	if len(dataKey) < MinDataKeyLen {
		return nil, fmt.Errorf("data key must be at least %d characters", MinDataKeyLen)
	}
	sum := sha256.Sum256([]byte(dataKey))
	return sum[:], nil
}

// Seal encrypts plaintext with AES-256-GCM using key (must be 16/24/32 bytes).
// The returned box is nonce || ciphertext||tag.
func Seal(key, plaintext []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("AES key must be 16, 24, or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	// Seal appends ciphertext+tag to the destination; prepend nonce for storage.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a box produced by Seal (nonce || ciphertext||tag).
func Open(key, box []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("AES key must be 16, 24, or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(box) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := box[:nonceSize], box[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plain, nil
}
