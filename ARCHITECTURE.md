
# SealDrop Architecture Note

## Scope posture

SealDrop is a package-centric encrypted file exchange utility, not a messaging system.
The architecture is intentionally small and split into narrow modules.

## Major components

1. `sealdrop/crypto.py`
   - Key derivation (scrypt)
   - AES-256-GCM encryption/decryption
   - Canonical JSON encoding and integrity helpers

2. `sealdrop/package.py`
   - `.sdpkg` binary format parser/writer
   - Encrypted payload assembly/parsing
   - Verify-before-extract logic
   - Extraction safety checks

3. `sealdrop/transfer.py`
   - Transport-agnostic artifact metadata (hash, size, optional TTL)
   - Session/handoff lifecycle helpers for operator workflows

4. `sealdrop/cli.py`
   - User-facing command surface
   - Exit code contract and JSON output modes
   - Passphrase retrieval via arg/env/file/prompt

## Trust boundaries

- **Trusted local endpoint boundary**: file content and passphrase handling rely on endpoint integrity.
- **Untrusted transport boundary**: `.sdpkg` artifacts may be intercepted/modified; tampering must be detected.
- **Untrusted input boundary**: package parser treats every package as adversarial input.

## Data flow

### Package creation

1. Read local plaintext file.
2. Build encrypted payload metadata (`file_name`, `file_size`, `file_sha256`, `sealed_at_utc`, optional note).
3. Serialize payload as: `[meta_len][meta_json][file_bytes]`.
4. Derive key from passphrase + random salt (scrypt).
5. Canonically encode header JSON and bind it as AES-GCM AAD (any header change breaks authentication).
6. Encrypt payload with AES-256-GCM using random 96-bit nonce.
7. Emit `.sdpkg`: `[magic][header_len][header_json][ciphertext]`.

### Verification

1. Parse and validate package magic/header, including canonical header encoding checks.
2. Derive key from header KDF params + passphrase.
3. Decrypt with AES-GCM using header bytes as AAD; fail closed on authentication failure.
4. Parse decrypted payload, validate schema and hash consistency.

### Extraction

1. Run full verification path first.
2. Validate decrypted filename against path traversal/absolute path abuse rules.
3. Write plaintext output only after all checks pass.

## Package format (high-level)

Visible header (plaintext JSON):
- format/version
- created timestamp
- KDF name/params/salt
- cipher name/nonce
- ciphertext length
- metadata policy notice

Encrypted payload:
- payload schema version
- file name
- file size
- file SHA-256
- package creation timestamp
- optional note
- raw file bytes

## Why this format

- Keeps parser simple and auditable.
- Preserves versioning hooks for future format changes.
- Reduces plaintext metadata exposure while retaining operational parseability.
