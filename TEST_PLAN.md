
# SealDrop Test Plan

## Unit tests

- Create -> inspect -> verify -> extract round trip.
- Header parser validation (magic/version/length mismatch).
- Payload parser validation (metadata schema, size/hash consistency).
- Transfer artifact TTL logic.

## Adversarial tests

- Wrong passphrase returns authentication failure.
- Ciphertext tampering detection.
- Header/ciphertext confusion (declared length mismatch).
- Payload integrity tamper detection (modified expected hash).

## Malformed package tests

- Invalid package magic.
- Truncated package/header structure.
- Invalid base64 in header fields.

## Extraction safety tests

- Reject path traversal/unsafe file names from decrypted metadata.
- Reject overwrite unless explicit flag provided.

## CLI regression tests

- JSON output contract for key commands.
- Exit code behavior for success/auth failure/format failure.
- End-to-end create/inspect/verify/extract via `python -m sealdrop.cli`.

## Open-source CI baseline

For public GitHub CI, keep this minimum command in every PR:

```bash
python3 -m unittest discover -s tests -p 'test_sealdrop*.py'
```

Recommended periodic jobs:
- malformed package fuzz/property pass
- release-sign script verification pass
- GUI smoke startup pass on Windows runner (if GUI binary is distributed)

## Interoperability and reproducibility notes

- Keep `.sdpkg` format versioned and parsable by deterministic field names.
- Use canonical JSON for structured metadata to reduce ambiguity.
- Add new tests before changing format fields or semantics.
