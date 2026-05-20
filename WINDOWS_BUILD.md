# SealDrop + SierraNode Windows Build Notes

This note keeps Windows build commands aligned with the current repository scripts.

## Preconditions

- Windows 10/11 x64 build host.
- Python 3.12+ installed.
- Build virtual environment created at `.venv_build_win`.
- Dependencies installed:

```powershell
python -m venv .venv_build_win
.\.venv_build_win\Scripts\python.exe -m pip install --upgrade pip setuptools wheel
.\.venv_build_win\Scripts\python.exe -m pip install -r requirements.txt
.\.venv_build_win\Scripts\python.exe -m pip install pyinstaller nuitka ordered-set zstandard
```

## Build commands

Run from repository root:

```powershell
# SierraNode standard CLI (PyInstaller)
.\scripts\build_windows_standard.ps1 -OutputName SierraNode_Absolute.exe -OutputDir BINARY

# SierraNode hardened CLI (Nuitka onefile)
.\scripts\build_hardened_windows.ps1 -OutputName SierraNode_Absolute_Hardened.exe -OutputDir BINARY

# SealDrop desktop GUI (PySide6 + PyInstaller)
.\scripts\build_sealdrop_gui_windows.ps1 -OutputName SealDrop_GUI.exe -OutputDir BINARY
```

Expected artifacts:

- `BINARY\SierraNode_Absolute.exe`
- `BINARY\SierraNode_Absolute_Hardened.exe`
- `BINARY\SealDrop_GUI.exe`

## Optional package mirror for GUI dependency install

If `PySide6` install from default index is unreliable:

```powershell
.\scripts\build_sealdrop_gui_windows.ps1 `
  -OutputName SealDrop_GUI.exe `
  -OutputDir BINARY `
  -InstallGuiDeps `
  -PackageIndexUrl "https://mirror-pypi.runflare.com/simple"
```

## Smoke checks

```powershell
.\BINARY\SierraNode_Absolute.exe --help
.\BINARY\SierraNode_Absolute_Hardened.exe --help
```

Launch GUI:

```powershell
.\BINARY\SealDrop_GUI.exe
```

## Common build/runtime issues

- If GUI binary copy fails with "file is being used by another process", close running `SealDrop_GUI.exe` processes and rerun build.
- SierraNode startup wrappers now write fatal startup traces to `%LOCALAPPDATA%\SierraNode\logs\startup_crash.log`.
- SealDrop GUI startup wrapper writes fatal startup traces to `%LOCALAPPDATA%\SealDrop\logs\startup_crash.log`.

## Open-source release note

If publishing SealDrop as a public GitHub project, use:
- `sealdrop/docs/OPEN_SOURCE_GITHUB_RELEASE.md` for repo-scope, release, and security hygiene steps.
- `scripts/sealdrop_release_sign.py` to publish signed `SHA256SUMS` with release artifacts.
