
# SealDrop MVP Implementation Plan

## Product statement

SealDrop is a local-first encrypted file transfer tool for direct, controlled exchange of sensitive files without relying on third-party file hosting.

## v1 (implemented now)

1. **Core crypto/package layer**
   - AES-256-GCM authenticated encryption
   - scrypt key derivation
   - `.sdpkg` package parser/writer with explicit versioning

2. **Local verification and extraction flow**
   - inspect header metadata
   - verify decrypt/auth/hash before output acceptance
   - safe extraction path checks

3. **CLI-first UX**
   - `seal|inspect|verify|extract` (+ `sign` for detached Ed25519 signatures)
   - passphrase via argument/env/file/prompt
   - JSON output for automation

4. **Documentation baseline**
   - README + quickstart + limitations
   - architecture note
   - threat model
   - CLI spec and test plan

5. **Test baseline**
   - round-trip tests
   - wrong-key/tamper tests
   - malformed package tests
   - traversal rejection tests
   - CLI regression tests

## v1.1 candidates

- one-time artifact token metadata policy (workflow-level, still transport-agnostic)
- optional TTL policy enforcement helper in CLI output
- stricter package lint/check command for enterprise automation

## v2 candidates (deferred)

- resumable transport helper protocol (if kept bounded and auditable)
- optional thin local web/desktop wrapper over CLI commands
- operator-controlled relay mode with clear trust boundaries

## Explicit deferrals to prevent scope creep

- chat/messaging features
- contact presence/social graph
- cloud sync and multi-device state
- broad anonymity/privacy-theater marketing claims
