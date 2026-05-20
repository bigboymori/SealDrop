# SealDrop GitHub Open-Source Release Checklist

This checklist is for publishing **SealDrop only** as a public open-source repository.

It is intentionally strict so the public repo stays clean, auditable, and easy to verify.

## 1) Scope boundary (must be explicit)

- Public repo contains the SealDrop project only (`sealdrop/`).
- Do **not** include SierraNode-only proprietary/commercial materials.
- Do **not** include private release keys, signing certificates, or internal secrets.

## 2) Create a SealDrop-only git branch

From the monorepo root:

```bash
git subtree split --prefix sealdrop -b sealdrop-open-source
```

Create a new GitHub repo (for example `your-org/sealdrop`) and push:

```bash
git push git@github.com:your-org/sealdrop.git sealdrop-open-source:main
```

## 3) Add standard open-source repository files

Before public launch, ensure the SealDrop repo has:

- `LICENSE` (Apache-2.0 for SealDrop)
- `README.md`
- `SECURITY.md` (reporting channel + disclosure expectations)
- `CONTRIBUTING.md` (dev/test/style expectations)
- `.github/workflows/ci.yml` (tests on PR and push)

## 4) Pre-publish safety checks

Run from repo root:

```bash
python3 -m unittest discover -s tests -p 'test_sealdrop*.py'
python3 scripts/sealdrop_release_sign.py --help
```

Manual checks:

- no private keys (`*.pem` private material) committed
- no PFX/certificate private bundles committed
- no tokens/API secrets in history or docs
- docs do not overclaim anonymity or guaranteed bypass outcomes

## 5) Build + release artifact verification

Generate release hash/signature files:

```bash
# one-time key generation (keep private key offline)
python3 scripts/sealdrop_release_sign.py keygen \
  --private-key ./release_keys/sealdrop_release_private_ed25519.pem \
  --public-key ./release_keys/sealdrop_release_public_ed25519.pem

# create signed SHA256SUMS for release artifacts
python3 scripts/sealdrop_release_sign.py generate \
  --artifact-dir ./release \
  --private-key ./release_keys/sealdrop_release_private_ed25519.pem

# verify before publishing
python3 scripts/sealdrop_release_sign.py verify \
  --artifact-dir ./release \
  --public-key ./release_keys/sealdrop_release_public_ed25519.pem
```

Publish with each GitHub Release:

- artifacts (`.sdpkg` samples, binaries if applicable)
- `SHA256SUMS`
- `SHA256SUMS.sig`
- `sealdrop_release_public_ed25519.pem`

## 6) Recommended GitHub repo settings

- Require PR review before merge to `main`.
- Require status checks (test workflow) before merge.
- Protect tags used for release versions.
- Use signed tags/releases where possible.
- Enable Dependabot/security alerts.

## 7) User verification instructions (for README/releases)

Document a minimal verification path:

```bash
python3 scripts/sealdrop_release_sign.py verify \
  --artifact-dir ./release \
  --public-key ./sealdrop_release_public_ed25519.pem
```

And package-level checks:

```bash
python3 -m sealdrop.cli inspect ./artifact.sdpkg --json
python3 -m sealdrop.cli verify ./artifact.sdpkg --passphrase "$SEALDROP_PASSPHRASE"
```

## 8) Final launch criteria

SealDrop public launch is ready when:

- tests pass
- docs are current
- release verification files are published
- trust boundaries and non-goals remain explicit
- no secret material exists in repo or release assets
