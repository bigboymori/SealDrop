# SealDrop

SealDrop is a local-first encrypted file transfer tool for direct, controlled exchange of sensitive files without relying on third-party file hosting.

License: Apache-2.0 (`sealdrop/LICENSE`).

## Identity and relationship to SierraNode

SealDrop is an unofficial adjacent project inspired by the engineering philosophy behind SierraNode.
It is intentionally narrower, easier to audit, and focused only on encrypted file exchange artifacts.

SealDrop is **not**:
- SierraNode rebranded
- a chat or messaging platform
- a cloud drive or sync suite
- an anonymity product making extreme privacy claims

## Open-source scope (GitHub)

SealDrop is ready to be published as a **standalone open-source project**.

Important boundary:
- Publish the `sealdrop/` project as its own repository.
- Do not publish proprietary SierraNode-only assets, commercial materials, private keys, or internal release secrets in that public repo.

Open-source publishing checklist: `sealdrop/docs/OPEN_SOURCE_GITHUB_RELEASE.md`
Quick start guide: `sealdrop/OPEN_SOURCE.md`

## What v1 does

- Encrypts files locally with AES-256-GCM (authenticated encryption).
- Uses scrypt for passphrase-based key derivation with explicit parameters in package header.
- Produces `.sdpkg` artifacts with format/versioning metadata and encrypted payload metadata.
- Enforces `.sdpkg` package extension for output artifacts (for example `important_stuff.sdpkg`).
- Verifies package authenticity and file integrity before extraction output is accepted.
- Rejects malformed/tampered packages and unsafe extraction filenames.
- Exposes a CLI-first interface with JSON output modes for automation.

## What metadata is visible

Package headers intentionally expose only operational metadata needed for parsing/derivation:
- package format/version
- package creation timestamp
- KDF/cipher identifiers and KDF parameters
- ciphertext length

File name, sender note, file size, and plaintext file bytes are inside encrypted payload.

## Quickstart

> Requirements: Python 3.10+ and `cryptography` (already listed in repo `requirements.txt`).

Generate a strong passphrase out-of-band (recommended) or use your own passphrase manager workflow.

```bash
# Create encrypted package
python3 -m sealdrop.cli seal ./secret.pdf --out ./important_stuff --passphrase "replace-with-strong-passphrase"

# Output is enforced to important_stuff.sdpkg

# Inspect visible header metadata
python3 -m sealdrop.cli inspect ./important_stuff.sdpkg

# Verify decrypt/auth/integrity without writing plaintext to disk
python3 -m sealdrop.cli verify ./important_stuff.sdpkg --passphrase "replace-with-strong-passphrase"

# Extract only after verification passes
python3 -m sealdrop.cli extract ./important_stuff.sdpkg --out-dir ./received --passphrase "replace-with-strong-passphrase"
```

## Passphrase guidance

- Minimum accepted by SealDrop: **12 characters**.
- Recommended for production use: **16-24+ random characters** or **4-6 random words**.
- Avoid reused account passwords, names, dates, and predictable phrases.
- Send passphrases through a different channel than the `.sdpkg` artifact.
- In the desktop GUI, the passphrase dialog now shows live strength and can generate a strong passphrase for you.

## CLI overview

- `sealdrop keygen`
- `sealdrop seal <file>`
- `sealdrop verify <package.sdpkg>`
- `sealdrop inspect <package.sdpkg>`
- `sealdrop extract <package.sdpkg>`
- `sealdrop sign <package.sdpkg>`

Full command and output contract: `sealdrop/docs/CLI_SPEC.md`

## Example flows

### Sender flow

1. Prepare the file locally.
2. Run `seal` with a strong passphrase and optional encrypted note.
3. Send `.sdpkg` through any transport you control (USB, internal ticketing, secure relay, etc.).
4. Send passphrase through a different channel.

### Receiver flow

1. Run `verify` with passphrase to confirm authentication/integrity first.
2. Run `inspect` to review visible format/KDF/cipher metadata.
3. If verification passes, run `extract`.

## Security notes

- Authentication failures are handled uniformly; tampering and wrong keys are treated as auth failure.
- Python zeroization is best-effort only and not a hard memory-erasure guarantee.
- Endpoint compromise (malware, keyloggers, hostile admin access) is out of scope.
- Transport metadata leakage is out of scope (network observers can still see file transfer timing/size).

## Limitations and non-goals

- No chat, identity graph, contact management, or group messaging.
- No cloud storage, history sync, or collaboration features.
- No hidden-network or anti-traffic-analysis claims.
- No resumable transfer in v1 (transport is user/operator chosen).

## Release verification (recommended process)

For official release bundles, publish:
- `SHA256SUMS`
- detached signature for `SHA256SUMS` (for example `SHA256SUMS.sig`)

Use helper script:

```bash
# 1) create signing keys
python3 scripts/sealdrop_release_sign.py keygen

# 2) create signed manifest for artifacts in ./release
python3 scripts/sealdrop_release_sign.py generate --artifact-dir ./release --private-key ./release_keys/sealdrop_release_private_ed25519.pem

# 3) verify manifest signature + artifact hashes
python3 scripts/sealdrop_release_sign.py verify --artifact-dir ./release --public-key ./release_keys/sealdrop_release_public_ed25519.pem
```

Receiver-side package checks:

```bash
python3 -m sealdrop.cli inspect ./important_stuff.sdpkg --json
python3 -m sealdrop.cli verify ./important_stuff.sdpkg --passphrase "$SEALDROP_PASSPHRASE"
```

For public GitHub releases, publish:
- release artifacts
- `SHA256SUMS`
- `SHA256SUMS.sig`
- public verification key (`sealdrop_release_public_ed25519.pem`)

## Included helper scripts

- Fast sender/receiver demo flow:
  - `scripts/sealdrop_demo.sh`
  - Runs create -> inspect -> verify -> extract against `important_stuff.sdpkg`.
- Release artifact signing and verification:
  - `scripts/sealdrop_release_sign.py`

## Desktop GUI (PySide6)

SealDrop now includes a thin desktop GUI layer that reuses backend modules directly.

- Launch: `python3 -m sealdrop.gui`
- Open a package directly (double-click style argument): `python3 -m sealdrop.gui ./artifact.sdpkg`
- UI flow is intentionally minimal: **Seal / Open / Verify / Verify Sig / Extract / Sign**
- Long-running operations run in background threads to keep UI responsive.
- Signature verification opens a dedicated signer-level trust dialog.
- Passphrase prompts are guided (minimum/recommended rules, strength meter, show/hide, and strong-passphrase generation).

## Windows binary build helpers

From repository root on Windows PowerShell:

```powershell
# SierraNode standard CLI binary
.\scripts\build_windows_standard.ps1 -OutputName SierraNode_Absolute.exe -OutputDir BINARY

# SierraNode hardened CLI binary
.\scripts\build_hardened_windows.ps1 -OutputName SierraNode_Absolute_Hardened.exe -OutputDir BINARY

# SealDrop desktop GUI binary
.\scripts\build_sealdrop_gui_windows.ps1 -OutputName SealDrop_GUI.exe -OutputDir BINARY
```

If your build environment needs a package mirror for PySide6 install during GUI build:

```powershell
.\scripts\build_sealdrop_gui_windows.ps1 `
  -OutputName SealDrop_GUI.exe `
  -OutputDir BINARY `
  -InstallGuiDeps `
  -PackageIndexUrl "https://mirror-pypi.runflare.com/simple"
```

## Documentation map

- Architecture: `sealdrop/docs/ARCHITECTURE.md`
- Command lifecycle recommendation: `sealdrop/docs/COMMAND_LIFECYCLE.md`
- Desktop GUI architecture: `sealdrop/docs/GUI_DESKTOP_ARCHITECTURE.md`
- GitHub open-source release checklist: `sealdrop/docs/OPEN_SOURCE_GITHUB_RELEASE.md`
- Windows build/run notes: `sealdrop/docs/WINDOWS_BUILD.md`
- CLI spec: `sealdrop/docs/CLI_SPEC.md`
- Threat model: `sealdrop/docs/THREAT_MODEL.md`
- MVP plan: `sealdrop/docs/MVP_IMPLEMENTATION_PLAN.md`
- Test plan: `sealdrop/docs/TEST_PLAN.md`
- Contribution guide: `sealdrop/CONTRIBUTING.md`
- Security policy: `sealdrop/SECURITY.md`
