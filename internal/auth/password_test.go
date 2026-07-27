package auth

import (
	"strings"
	"testing"
)

func TestHashPasswordAndCheck(t *testing.T) {
	const password = "correct horse battery staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty hash")
	}
	if hash == password {
		t.Fatal("hash must not equal plaintext password")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash prefix = %q, want $argon2id$", hash[:min(20, len(hash))])
	}
	if !CheckPassword(hash, password) {
		t.Error("CheckPassword(hash, correct) = false, want true")
	}
	if CheckPassword(hash, "wrong-password") {
		t.Error("CheckPassword(hash, wrong) = true, want false")
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	const password = "same-password-twice"
	h1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword #1: %v", err)
	}
	h2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword #2: %v", err)
	}
	if h1 == h2 {
		t.Error("expected different hashes for independent salts")
	}
	if !CheckPassword(h1, password) || !CheckPassword(h2, password) {
		t.Error("both hashes should verify the original password")
	}
}

func TestHashPasswordEmpty(t *testing.T) {
	_, err := HashPassword("")
	if err == nil {
		t.Fatal("HashPassword(\"\") = nil error, want error")
	}
}

func TestCheckPasswordInvalidHash(t *testing.T) {
	if CheckPassword("", "password") {
		t.Error("empty hash should not verify")
	}
	if CheckPassword("not-a-valid-hash", "password") {
		t.Error("garbage hash should not verify")
	}
	if CheckPassword("$argon2id$v=19$m=65536,t=1,p=1$YWFh$YmJi", "password") {
		t.Error("malformed/short argon2 params should not verify")
	}
	// bcrypt-looking string is not supported for HashPassword output; Check returns false.
	if CheckPassword("$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012", "password") {
		t.Error("bcrypt-looking hash should not verify via argon2 path")
	}
}

func TestCheckPasswordRejectsArgon2i(t *testing.T) {
	// Only argon2id is accepted (variant string must be argon2id).
	fake := "$argon2i$v=19$m=65536,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFz"
	if CheckPassword(fake, "anything") {
		t.Error("argon2i hash must be rejected")
	}
}
