package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Signer signs payloads and provides key identity. All OCEAN attestation
// operations use this interface, enabling alternative key backends (HSM, KMS)
// in the future while keeping the core signing logic uniform.
type Signer interface {
	// Sign produces a cryptographic signature over the given payload.
	Sign(payload []byte) ([]byte, error)

	// KeyID returns a short, human-readable identifier derived from the
	// public key (hex of the first 8 bytes of the SHA-256 of the public key).
	KeyID() string

	// PublicKey returns the Ed25519 public key for verification.
	PublicKey() ed25519.PublicKey
}

// Ed25519Signer implements Signer with Ed25519 keys.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
}

// GenerateKeyPair creates a new Ed25519 keypair and saves both keys as PEM
// files in keyDir. The private key is stored with restrictive permissions
// (0600). Returns the paths to the public and private key files.
func GenerateKeyPair(keyDir string) (pubPath, privPath string, err error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return "", "", fmt.Errorf("creating key directory: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating Ed25519 key pair: %w", err)
	}

	pubPath = filepath.Join(keyDir, "ocean-ed25519.pub")
	privPath = filepath.Join(keyDir, "ocean-ed25519.key")

	// Encode public key as PEM with raw 32-byte public key.
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte(pub),
	})
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return "", "", fmt.Errorf("writing public key: %w", err)
	}

	// Encode private key as PEM with raw 32-byte seed.
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priv.Seed(),
	})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return "", "", fmt.Errorf("writing private key: %w", err)
	}

	return pubPath, privPath, nil
}

// LoadSigner loads an Ed25519 signer from a PEM-encoded private key file.
// The PEM block must contain the 32-byte Ed25519 seed.
func LoadSigner(privKeyPath string) (*Ed25519Signer, error) {
	data, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", privKeyPath)
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q, want PRIVATE KEY", block.Type)
	}

	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size %d, want %d", len(block.Bytes), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(block.Bytes)
	return NewEd25519Signer(priv), nil
}

// NewEd25519Signer creates a signer from raw Ed25519 key material. The key ID
// is derived from the SHA-256 hash of the public key (first 8 bytes, hex-encoded).
func NewEd25519Signer(priv ed25519.PrivateKey) *Ed25519Signer {
	pub := priv.Public().(ed25519.PublicKey)
	hash := sha256.Sum256(pub)
	keyID := hex.EncodeToString(hash[:8])

	return &Ed25519Signer{
		privateKey: priv,
		publicKey:  pub,
		keyID:      keyID,
	}
}

// Sign produces an Ed25519 signature over the given payload.
func (s *Ed25519Signer) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, payload), nil
}

// KeyID returns the hex-encoded first 8 bytes of the SHA-256 hash of the
// public key, providing a short stable identifier for the signing key.
func (s *Ed25519Signer) KeyID() string {
	return s.keyID
}

// PublicKey returns the Ed25519 public key associated with this signer.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return s.publicKey
}

// ExportPublicKey writes the signer's public key to a PEM file at the given
// path. The file is created with permissions 0644 (world-readable). This
// enables third-party verification of OCEAN attestations.
func ExportPublicKey(signer Signer, path string) error {
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte(signer.PublicKey()),
	})
	if err := os.WriteFile(path, pubPEM, 0644); err != nil {
		return fmt.Errorf("writing public key to %s: %w", path, err)
	}
	return nil
}

// LoadPublicKey loads an Ed25519 public key from a PEM-encoded file. The PEM
// block must have type "PUBLIC KEY" and contain the raw 32-byte Ed25519 public
// key. This is used for third-party verification of OCEAN attestations.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q, want PUBLIC KEY", block.Type)
	}

	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size %d, want %d", len(block.Bytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(block.Bytes), nil
}
