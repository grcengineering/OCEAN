---
id: crypto
severity: high
applies_to: [all]
---

# Cryptography

Use vetted primitives from the platform's standard library — never invent.

DO:
- Use high-level, misuse-resistant APIs (e.g. libsodium-style, WebCrypto,
  language-standard AEAD) with authenticated encryption (AES-GCM,
  ChaCha20-Poly1305).
- Generate keys, IVs, tokens, and salts with a cryptographically secure RNG
  (crypto.getRandomValues / secrets module equivalents).
- Use a fresh, unique nonce/IV per encryption; never reuse with the same key.
- Hash passwords with argon2id/bcrypt/scrypt (dedicated KDFs), not fast hashes.
- Use TLS for data in transit with certificate verification left ON.

DON'T:
- Don't implement your own ciphers, protocols, padding, or comparisons;
  use constant-time comparison helpers for secret material.
- Don't use MD5/SHA-1 for security purposes or ECB mode anywhere.
- Don't seed security decisions from Math.random()-style PRNGs.
- Don't disable TLS verification, even "temporarily" in dev code paths.
