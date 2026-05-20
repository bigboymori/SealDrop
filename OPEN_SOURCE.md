# SealDrop Open Source Checklist

Use this when you are ready to publish SealDrop on GitHub as a public repo.

## 1) Lock the scope

- Publish only the `sealdrop/` project.
- Do not include SierraNode commercial files, private keys, or internal release materials.
- Keep the repo focused on file packaging, verification, extraction, docs, and tests.

## 2) Clean the tree

- Remove secrets, tokens, certificates, and private key files.
- Remove any files that are not meant for public release.
- Confirm docs do not overclaim anonymity, stealth, or bypass guarantees.

## 3) Add the public repo basics

- `LICENSE` (Apache-2.0, already selected for SealDrop)
- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- CI workflow under `.github/workflows/`

## 4) Run checks

```bash
python3 -m unittest discover -s tests -p 'test_sealdrop*.py'
python3 scripts/sealdrop_release_sign.py --help
```

## 5) Split the public repo

```bash
git subtree split --prefix sealdrop -b sealdrop-open-source
git push git@github.com:YOUR_ORG/YOUR_SEALDROP_REPO.git sealdrop-open-source:main
```

## 6) Prepare release verification

```bash
python3 scripts/sealdrop_release_sign.py keygen
python3 scripts/sealdrop_release_sign.py generate --artifact-dir ./release --private-key ./release_keys/sealdrop_release_private_ed25519.pem
python3 scripts/sealdrop_release_sign.py verify --artifact-dir ./release --public-key ./release_keys/sealdrop_release_public_ed25519.pem
```

## 7) Publish the GitHub release

- Upload release artifacts.
- Include `SHA256SUMS`.
- Include `SHA256SUMS.sig`.
- Include the public verification key.

## 8) Verify from a clean clone

- Clone the public repo fresh.
- Run the tests again.
- Verify the release manifest and package outputs.
- Confirm the README and threat model match the published scope.
