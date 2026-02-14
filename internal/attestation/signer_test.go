package attestation_test

import (
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/grcengineering/ocean/internal/attestation"
)

func TestGenerateKeyPair(t *testing.T) {
	keyDir := t.TempDir()

	pubPath, privPath, err := attestation.GenerateKeyPair(keyDir)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Verify file paths are correct.
	wantPub := filepath.Join(keyDir, "ocean-ed25519.pub")
	wantPriv := filepath.Join(keyDir, "ocean-ed25519.key")
	if pubPath != wantPub {
		t.Errorf("pubPath = %q, want %q", pubPath, wantPub)
	}
	if privPath != wantPriv {
		t.Errorf("privPath = %q, want %q", privPath, wantPriv)
	}

	// Verify files exist and are readable.
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("reading public key: %v", err)
	}
	privData, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("reading private key: %v", err)
	}

	// Verify PEM structure.
	pubBlock, _ := pem.Decode(pubData)
	if pubBlock == nil {
		t.Fatal("public key file is not valid PEM")
	}
	if pubBlock.Type != "PUBLIC KEY" {
		t.Errorf("public key PEM type = %q, want %q", pubBlock.Type, "PUBLIC KEY")
	}
	if len(pubBlock.Bytes) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(pubBlock.Bytes), ed25519.PublicKeySize)
	}

	privBlock, _ := pem.Decode(privData)
	if privBlock == nil {
		t.Fatal("private key file is not valid PEM")
	}
	if privBlock.Type != "PRIVATE KEY" {
		t.Errorf("private key PEM type = %q, want %q", privBlock.Type, "PRIVATE KEY")
	}
	if len(privBlock.Bytes) != ed25519.SeedSize {
		t.Errorf("private key seed size = %d, want %d", len(privBlock.Bytes), ed25519.SeedSize)
	}

	// Verify private key file permissions are restricted.
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("private key permissions = %o, want 0600", mode)
	}
}

func TestLoadSigner(t *testing.T) {
	keyDir := t.TempDir()

	_, privPath, err := attestation.GenerateKeyPair(keyDir)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	signer, err := attestation.LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// KeyID should be a 16-character hex string (8 bytes).
	keyID := signer.KeyID()
	if len(keyID) != 16 {
		t.Errorf("KeyID length = %d, want 16 (hex of 8 bytes)", len(keyID))
	}

	// PublicKey should be non-nil and correct size.
	pub := signer.PublicKey()
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("PublicKey size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestSignAndVerify(t *testing.T) {
	keyDir := t.TempDir()

	_, privPath, err := attestation.GenerateKeyPair(keyDir)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	signer, err := attestation.LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	payload := []byte("test payload for signing")
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify signature using standard library.
	if !ed25519.Verify(signer.PublicKey(), payload, sig) {
		t.Error("signature verification failed: valid signature was not accepted")
	}

	// Verify that a tampered payload fails.
	tampered := []byte("tampered payload")
	if ed25519.Verify(signer.PublicKey(), tampered, sig) {
		t.Error("signature verification succeeded on tampered payload: should have failed")
	}
}

func TestNewEd25519Signer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	signer := attestation.NewEd25519Signer(priv)

	// Verify public key matches.
	if !signer.PublicKey().Equal(pub) {
		t.Error("PublicKey() does not match the key used to create signer")
	}

	// Verify signing works.
	payload := []byte("hello world")
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		t.Error("signature verification failed")
	}
}

func TestLoadSigner_InvalidFile(t *testing.T) {
	// Non-existent file.
	_, err := attestation.LoadSigner("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("LoadSigner() with non-existent file should return error")
	}

	// Invalid PEM content.
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.key")
	if err := os.WriteFile(badFile, []byte("not a pem file"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = attestation.LoadSigner(badFile)
	if err == nil {
		t.Error("LoadSigner() with invalid PEM should return error")
	}
}

func TestGenerateKeyPair_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "nested", "keys")

	pubPath, privPath, err := attestation.GenerateKeyPair(keyDir)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Verify files were created in the nested directory.
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("public key file not created: %v", err)
	}
	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key file not created: %v", err)
	}
}
