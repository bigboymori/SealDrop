# SealDrop Security Policy

## Supported versions

Security fixes are applied to the latest active SealDrop version line.

## Reporting a vulnerability

Please report suspected vulnerabilities privately first.

Include:
- affected version/commit
- reproduction steps
- impact summary
- proof-of-concept artifacts if safe to share

Do not publish full exploit details until a fix is available and release guidance is posted.

## Security posture boundaries

SealDrop provides:
- local file encryption (AES-256-GCM)
- tamper detection/authentication checks
- safe parsing and extraction controls

SealDrop does not guarantee:
- endpoint compromise resistance
- traffic-analysis anonymity
- universal bypass/stealth outcomes

When reporting issues, distinguish clearly between:
- implementation bugs (in-scope)
- deployment/operational misuse
- non-goal assumptions documented in `docs/THREAT_MODEL.md`
