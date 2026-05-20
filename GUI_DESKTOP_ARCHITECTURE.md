# SealDrop Desktop GUI Architecture (PySide6)

## Scope

The desktop app is a thin UI layer over existing backend modules:

- `sealdrop/package.py`
- `sealdrop/crypto.py`
- `sealdrop/transfer.py`
- `sealdrop/constants.py`
- `sealdrop/signature.py`

No cryptographic or package parsing logic is duplicated in the GUI.

## Visual model

The interface is intentionally WinRAR/7-Zip-like:

- **Top toolbar**: Seal / Open / Verify / Verify Sig / Extract / Sign
- **Center view**: package content list (single-file entry for v1)
- **Right panel**: metadata + verification/signature status
- **Bottom trust log**: timestamped operation and trust events
- **Status bar**: short operation results

Primary lifecycle in UI:

**seal -> inspect/open -> verify -> extract**

Practical UX additions in this pass:
- keyboard shortcuts (`Ctrl+S`, `Ctrl+O`, `Ctrl+Shift+V`, `Ctrl+Shift+G`, `Ctrl+E`, `Ctrl+G`)
- menu bar actions for file/operation flows
- non-blocking worker-thread execution for seal/open/verify/extract/sign operations
- busy cursor + temporary action disable while background operations run
- dedicated signature verification dialog with signer-level PASS/FAIL/UNKNOWN details
- manual signature verification now updates trust color state (green/red/gray)
- guided passphrase dialog with minimum/recommended rules, strength indicator, and one-click strong passphrase generation
- optional deterministic sealing prompt for reproducible artifacts

## Drag/drop behavior

- Drop regular file: prompt to seal into `.sdpkg`
- Drop `.sdpkg`: open package and auto-run inspect + verify flow

## File association behavior

`sealdrop.gui.main_window` accepts an optional package path argument.

When started with a `.sdpkg` path, it opens package and attempts inspect/verify in the same session.

## Module map

- `sealdrop/gui/main_window.py`: app bootstrap + orchestration
- `sealdrop/gui/toolbar.py`: toolbar actions
- `sealdrop/gui/package_view.py`: center package table
- `sealdrop/gui/metadata_panel.py`: right-side metadata + trust state
- `sealdrop/gui/dialogs.py`: passphrase/file/key dialogs
- `sealdrop/gui/dragdrop.py`: drop routing logic
- `sealdrop/gui/async_worker.py`: threadpool task runner for non-blocking operations
- `sealdrop/gui/signature_dialog.py`: signature verification details dialog
- `sealdrop/gui/trust_log.py`: timestamped trust/event log

## Status colors

- Green: verified
- Red: failed
- Gray: unknown / not yet verified

## Why this design

- Keeps the product fast and understandable.
- Preserves backend as single security authority.
- Gives non-CLI users a practical path without changing trust boundaries.
