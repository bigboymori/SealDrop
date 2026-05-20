# Contributing to SealDrop

Thanks for helping improve SealDrop.

SealDrop is intentionally small, auditable, and scope-bounded. Contributions should preserve that design.

## Scope guardrails

Please do not expand SealDrop into:
- chat/messaging features
- cloud sync/storage platform behavior
- identity graph/social features
- anonymity or anti-censorship marketing claims

If a proposal changes the product shape, open an issue first before implementing.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

## Required checks before PR

```bash
python3 -m unittest discover -s tests -p 'test_sealdrop*.py'
```

If your changes touch packaging/signature logic, also run:

```bash
python3 scripts/sealdrop_release_sign.py --help
```

## Coding expectations

- Keep dependencies minimal.
- Preserve CLI behavior and exit code contracts.
- Keep error handling uniform and non-oracle-like.
- Add tests for malformed/adversarial cases when touching parser/crypto/package code.
- Update docs when behavior changes.

## Pull requests

PRs should include:
- what changed
- why the change is needed
- test coverage summary
- any format/compatibility impact
