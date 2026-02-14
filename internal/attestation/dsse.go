package attestation

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// DSSEEnvelope represents a Dead Simple Signing Envelope (DSSE) as defined
// by the DSSE specification. It wraps an arbitrary payload with one or more
// cryptographic signatures using Pre-Authentication Encoding (PAE) to prevent
// confused-deputy attacks.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// DSSESignature holds a single signature within a DSSE envelope, along with
// the key ID that produced it.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// CreateDSSEEnvelope creates a signed DSSE envelope for the given statement.
// The statement (typically an in-toto statement JSON) is base64-encoded as the
// payload. The PAE (Pre-Authentication Encoding) of the payload type and raw
// statement bytes is signed, preventing type-confusion attacks.
func CreateDSSEEnvelope(statement []byte, signer Signer) (*DSSEEnvelope, error) {
	payloadType := "application/vnd.in-toto+json"

	// Base64-encode the statement as the envelope payload.
	payloadB64 := base64.StdEncoding.EncodeToString(statement)

	// Compute PAE and sign it (PAE uses raw bytes, not base64).
	pae := PAE(payloadType, statement)
	sig, err := signer.Sign(pae)
	if err != nil {
		return nil, fmt.Errorf("signing PAE: %w", err)
	}

	return &DSSEEnvelope{
		PayloadType: payloadType,
		Payload:     payloadB64,
		Signatures: []DSSESignature{
			{
				KeyID: signer.KeyID(),
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}, nil
}

// PAE computes the DSSE Pre-Authentication Encoding. The format is:
//
//	"DSSEv1" + " " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
//
// This encoding binds the payload type to the payload, preventing an attacker
// from reinterpreting a signed payload under a different type.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), string(payload)))
}

// VerifyDSSEEnvelope verifies a DSSE envelope against a given Ed25519 public
// key. It checks that at least one signature in the envelope is valid over
// the PAE of the payload type and decoded payload.
func VerifyDSSEEnvelope(envelope *DSSEEnvelope, publicKey ed25519.PublicKey) error {
	if len(envelope.Signatures) == 0 {
		return fmt.Errorf("envelope has no signatures")
	}

	// Decode the base64 payload back to raw bytes for PAE computation.
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decoding payload: %w", err)
	}

	pae := PAE(envelope.PayloadType, payload)

	for _, dsig := range envelope.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(dsig.Sig)
		if err != nil {
			continue
		}

		if ed25519.Verify(publicKey, pae, sigBytes) {
			return nil
		}
	}

	return fmt.Errorf("no valid signature found for the provided public key")
}
