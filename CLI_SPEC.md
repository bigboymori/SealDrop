# SealDrop CLI Specification (v1)

## Primary command set (memorable lifecycle)

- `sealdrop seal <file>`
- `sealdrop verify <package.sdpkg>`
- `sealdrop inspect <package.sdpkg>`
- `sealdrop extract <package.sdpkg>`
- `sealdrop sign <package.sdpkg>`

Lifecycle: **seal -> verify -> inspect -> extract**

Compatibility note: legacy `sealdrop package ...` subcommands remain available.

## Global behavior

- Human-readable output by default.
- `--json` supported on core operations.
- Exit codes are stable and script-friendly.

Exit codes:
- `0`: success
- `2`: CLI usage/argparse error
- `3`: authentication failure (wrong key or tampered ciphertext)
- `4`: malformed/unsupported package format
- `5`: extraction safety violation
- `6`: configuration/input/signature validation error

## `sealdrop seal <file>`

Build an encrypted `.sdpkg` artifact.

Example:

```bash
python3 -m sealdrop.cli seal ./secret.pdf --out ./important_stuff --passphrase "strong-passphrase"
```

Key args:
- positional `<file>` input path
- `--out` output package path (default: `<file>.sdpkg`)
- `--passphrase` or `--passphrase-env` or `--passphrase-file`
- passphrase minimum: 12 characters (recommended: 16+ random characters or 4+ random words)
- `--note` optional encrypted note
- `--scrypt-n|r|p` advanced KDF tuning
- `--deterministic` reproducible package mode

Output naming behavior:
- SealDrop enforces `.sdpkg` extension.
- Example: `--out ./important_stuff` produces `important_stuff.sdpkg`.

## `sealdrop inspect <package.sdpkg>`

Read package header without decrypting payload.

Example:

```bash
python3 -m sealdrop.cli inspect ./important_stuff.sdpkg --json
```

Output fields (`--json`):
- `package_path`
- `package_sha256`
- `package_size`
- `format`
- `version`
- `created_utc`
- `cipher`
- `kdf`
- `ciphertext_len`
- `metadata_policy`

## `sealdrop verify <package.sdpkg>`

Verify decrypt/auth/integrity without writing plaintext output.

Example:

```bash
python3 -m sealdrop.cli verify ./important_stuff.sdpkg --passphrase "strong-passphrase"
```

Optional signature checks:

```bash
python3 -m sealdrop.cli verify ./important_stuff.sdpkg \
  --passphrase "strong-passphrase" \
  --public-key alice=./alice.pub.pem \
  --public-key bob=./bob.pub.pem
```

Expected behavior:
- auth failure -> exit `3`
- malformed package -> exit `4`
- signature failures (when checked) -> exit `6`

## `sealdrop extract <package.sdpkg>`

Verify then extract file into output directory.

Example:

```bash
python3 -m sealdrop.cli extract ./important_stuff.sdpkg --out-dir ./received --passphrase "strong-passphrase"
```

Safety behavior:
- rejects path traversal and absolute-like filename abuse
- refuses overwrite unless `--overwrite` is supplied
- writes via atomic replace and verifies extracted hash/size consistency

## `sealdrop sign <package.sdpkg>`

Create or append Ed25519 detached signature records in `<package>.sig.json`.

Example:

```bash
python3 -m sealdrop.cli sign ./important_stuff.sdpkg \
  --private-key ./alice.private.pem \
  --signer alice
```

Supports multiple signatures by appending signer records in the same sidecar.

## `sealdrop keygen`

Generates random bytes for operator workflows.

Example:

```bash
python3 -m sealdrop.cli keygen --bytes 32 --json
```
