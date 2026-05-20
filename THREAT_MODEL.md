
# SealDrop Threat Model (v1)

## Assets

- Plaintext file content
- File integrity/authenticity state
- Passphrase/key material
- Package metadata trust signals

## Attackers

1. Network/transport attacker
   - Can capture, replay, reorder, or modify `.sdpkg` artifacts.
2. Malicious package sender
   - Can send malformed packages and malicious metadata.
3. Curious intermediary
   - Can observe package size/timing and plaintext header fields.

## Primary assumptions

- Sender and receiver endpoints are not already fully compromised.
- Receiver verifies package before extraction.
- Passphrase exchange happens out-of-band over a separate channel.

## Security goals

- Confidentiality of file content and encrypted payload metadata at rest/in transit.
- Authenticated tamper detection on package ciphertext.
- Safe parsing and safe extraction path controls for adversarial package inputs.

## Non-goals

- Anonymity against network-level traffic analysis.
- Endpoint compromise resistance (malware/keylogger/root compromise).
- Identity/authentication framework for human users (no contact graph, no PKI identity layer in v1).
- Reliable transport/session semantics (resumable protocol, queueing, delivery guarantees).

## Key mitigations

- AES-256-GCM for authenticated encryption.
- scrypt KDF with explicit parameters and random salt.
- Strict package magic/version/header checks.
- Uniform authentication failure behavior for wrong key vs tampering.
- Decrypted payload schema and SHA-256 consistency checks.
- Path traversal and unsafe filename rejection during extraction.

## Residual risks

- Package size and timing metadata leakage remains.
- Human passphrase quality can be weak.
- Python memory management limits strict key material zeroization guarantees.
- Replay of old valid package artifacts is possible unless external workflow adds one-time/TTL controls.

## Honest security statement

SealDrop is a small encrypted file exchange utility with bounded guarantees.
It improves confidentiality/integrity for controlled file handoff, but it is not a full anonymity, endpoint-hardening, or identity-trust platform.
