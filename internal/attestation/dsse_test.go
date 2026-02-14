package attestation_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/grcengineering/ocean/internal/attestation"
)

func TestCreateDSSEEnvelope(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	signer := attestation.NewEd25519Signer(priv)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[]}`)

	envelope, err := attestation.CreateDSSEEnvelope(statement, signer)
	if err != nil {
		t.Fatalf("CreateDSSEEnvelope() error = %v", err)
	}

	// Verify payload type.
	if envelope.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("PayloadType = %q, want %q", envelope.PayloadType, "application/vnd.in-toto+json")
	}

	// Verify payload is valid base64 and decodes to original statement.
	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	if string(decoded) != string(statement) {
		t.Errorf("decoded payload = %q, want %q", string(decoded), string(statement))
	}

	// Verify there is exactly one signature.
	if len(envelope.Signatures) != 1 {
		t.Fatalf("Signatures count = %d, want 1", len(envelope.Signatures))
	}

	// Verify keyID matches signer.
	if envelope.Signatures[0].KeyID != signer.KeyID() {
		t.Errorf("Signature KeyID = %q, want %q", envelope.Signatures[0].KeyID, signer.KeyID())
	}

	// Verify signature is valid base64.
	sigBytes, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}

	// Verify signature over PAE.
	pae := attestation.PAE(envelope.PayloadType, statement)
	if !ed25519.Verify(pub, pae, sigBytes) {
		t.Error("PAE signature verification failed")
	}
}

func TestVerifyDSSEEnvelope(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	signer := attestation.NewEd25519Signer(priv)

	statement := []byte(`{"test":"data"}`)
	envelope, err := attestation.CreateDSSEEnvelope(statement, signer)
	if err != nil {
		t.Fatalf("CreateDSSEEnvelope() error = %v", err)
	}

	// Valid verification should succeed.
	if err := attestation.VerifyDSSEEnvelope(envelope, pub); err != nil {
		t.Errorf("VerifyDSSEEnvelope() error = %v, want nil", err)
	}

	// Verification with wrong key should fail.
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	if err := attestation.VerifyDSSEEnvelope(envelope, otherPub); err == nil {
		t.Error("VerifyDSSEEnvelope() with wrong key should return error")
	}
}

func TestVerifyDSSEEnvelope_TamperedPayload(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	signer := attestation.NewEd25519Signer(priv)

	statement := []byte(`{"test":"data"}`)
	envelope, err := attestation.CreateDSSEEnvelope(statement, signer)
	if err != nil {
		t.Fatalf("CreateDSSEEnvelope() error = %v", err)
	}

	// Tamper with the payload.
	tampered := base64.StdEncoding.EncodeToString([]byte(`{"test":"tampered"}`))
	envelope.Payload = tampered

	if err := attestation.VerifyDSSEEnvelope(envelope, signer.PublicKey()); err == nil {
		t.Error("VerifyDSSEEnvelope() with tampered payload should return error")
	}
}

func TestPAE(t *testing.T) {
	payloadType := "application/vnd.in-toto+json"
	payload := []byte("hello")

	pae := attestation.PAE(payloadType, payload)

	// Verify PAE format: "DSSEv1 <len_type> <type> <len_payload> <payload>"
	expected := "DSSEv1 28 application/vnd.in-toto+json 5 hello"
	if string(pae) != expected {
		t.Errorf("PAE() = %q, want %q", string(pae), expected)
	}
}

func TestDSSEEnvelopeJSON(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	signer := attestation.NewEd25519Signer(priv)

	statement := []byte(`{"test":"json"}`)
	envelope, err := attestation.CreateDSSEEnvelope(statement, signer)
	if err != nil {
		t.Fatalf("CreateDSSEEnvelope() error = %v", err)
	}

	// Verify envelope serializes to valid JSON.
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Verify it deserializes back.
	var roundTripped attestation.DSSEEnvelope
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if roundTripped.PayloadType != envelope.PayloadType {
		t.Errorf("PayloadType mismatch after round-trip")
	}
	if roundTripped.Payload != envelope.Payload {
		t.Errorf("Payload mismatch after round-trip")
	}
	if len(roundTripped.Signatures) != len(envelope.Signatures) {
		t.Errorf("Signatures count mismatch after round-trip")
	}
}

func TestVerifyDSSEEnvelope_NoSignatures(t *testing.T) {
	envelope := &attestation.DSSEEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte("test")),
		Signatures:  []attestation.DSSESignature{},
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	if err := attestation.VerifyDSSEEnvelope(envelope, pub); err == nil {
		t.Error("VerifyDSSEEnvelope() with no signatures should return error")
	}
}
