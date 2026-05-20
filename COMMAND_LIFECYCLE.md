# SealDrop Command Lifecycle Recommendation

## Memorable core command set

Use a compact, distinct command set centered on the `.sdpkg` artifact:

- `sealdrop seal <file>`
- `sealdrop verify <package.sdpkg>`
- `sealdrop inspect <package.sdpkg>`
- `sealdrop extract <package.sdpkg>`
- `sealdrop sign <package.sdpkg>`

This is easier to remember than generic `encrypt/decrypt` naming because it maps to the product identity (`SealDrop` + sealed package flow), not just cryptographic primitives.

## Why this lifecycle sticks

**seal -> verify -> inspect -> extract** works because it matches user intent:

1. **Seal** creates a transferable artifact.
2. **Verify** answers the trust question first (safe-by-default).
3. **Inspect** shows visible metadata and policy details without unpacking.
4. **Extract** happens only after trust checks pass.

Even though `inspect` can be run at any time, putting `verify` first keeps the default behavior conservative.

## Organic format spread

Automatic output naming like `report.pdf.sdpkg` helps adoption because users see and forward a recognizable extension in normal workflows.

This small naming choice reinforces:
- package identity
- user confidence in what is being transferred
- easier support/documentation language ("send the `.sdpkg`")

## Focus now, extend later

Initial CLI should stay tight around the lifecycle above.

Reasonable future additions:
- `keygen`
- recipient workflows (`--recipient`)
- deterministic/reproducible modes

But these should remain additive and not dilute the primary mental model.
