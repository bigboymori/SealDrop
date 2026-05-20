"""SealDrop CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import sys
from getpass import getpass
from pathlib import Path

from .crypto import ScryptParams, b64e, secure_random_bytes
from .errors import AuthenticationError, ConfigError, PackageFormatError, SafetyError
from .package import create_package, extract_package, inspect_package, verify_package
from .signature import parse_public_key_mappings, sign_package, verify_signatures

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_FORMAT = 4
EXIT_SAFETY = 5
EXIT_CONFIG = 6


def _print_json(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True, indent=2))


def _resolve_passphrase(args: argparse.Namespace, *, for_create: bool) -> str:
    if getattr(args, "passphrase", None):
        return args.passphrase

    env_name = getattr(args, "passphrase_env", None)
    if env_name:
        value = os.getenv(env_name)
        if value:
            return value
        raise ConfigError(f"passphrase environment variable is empty or missing: {env_name}")

    file_path = getattr(args, "passphrase_file", None)
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8").strip()
        if not text:
            raise ConfigError("passphrase file is empty")
        return text

    prompt = "SealDrop passphrase: "
    if for_create:
        first = getpass(prompt=prompt)
        second = getpass(prompt="Confirm passphrase: ")
        if first != second:
            raise ConfigError("passphrase confirmation mismatch")
        return first
    return getpass(prompt=prompt)


def _add_passphrase_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--passphrase", help="direct passphrase value (automation only)")
    parser.add_argument("--passphrase-env", help="environment variable holding passphrase")
    parser.add_argument("--passphrase-file", help="path to a file containing passphrase")


def _cmd_keygen(args: argparse.Namespace) -> int:
    key = secure_random_bytes(args.bytes)
    payload = {
        "kind": "random-bytes",
        "bytes": args.bytes,
        "value_b64": b64e(key),
        "note": "This is random entropy. SealDrop package encryption normally uses a passphrase + scrypt.",
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"random_bytes_b64={payload['value_b64']}")
        print(payload["note"])
    return EXIT_OK


def _default_output_for_input(input_path: Path) -> Path:
    # Memorable output naming helps `.sdpkg` spread naturally in handoff workflows.
    return input_path.with_name(input_path.name + ".sdpkg")


def _cmd_seal(args: argparse.Namespace) -> int:
    input_path = Path(args.input_file)
    output_path = Path(args.output_package) if args.output_package else _default_output_for_input(input_path)
    passphrase = _resolve_passphrase(args, for_create=True)
    result = create_package(
        input_path=input_path,
        output_path=output_path,
        passphrase=passphrase,
        note=args.note,
        scrypt_params=ScryptParams(n=args.scrypt_n, r=args.scrypt_r, p=args.scrypt_p),
        deterministic=args.deterministic,
    )
    payload = {
        "status": "ok",
        "package_path": str(result.package_path),
        "package_sha256": result.package_sha256,
        "package_size": result.package_size,
        "file_sha256": result.file_sha256,
        "file_size": result.file_size,
        "created_utc": result.created_utc,
        "deterministic": bool(args.deterministic),
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"sealed: {result.package_path}")
        print(f"package_sha256: {result.package_sha256}")
        print(f"file_sha256: {result.file_sha256}")
        print(f"deterministic_mode: {'on' if args.deterministic else 'off'}")
    return EXIT_OK


def _cmd_inspect(args: argparse.Namespace) -> int:
    result = inspect_package(Path(args.package_file))
    payload = {
        "status": "ok",
        "package_path": str(result.package_path),
        "package_sha256": result.package_sha256,
        "package_size": result.package_size,
        "format": result.format,
        "version": result.version,
        "created_utc": result.created_utc,
        "cipher": result.cipher,
        "kdf": result.kdf,
        "ciphertext_len": result.ciphertext_len,
        "metadata_policy": result.metadata_policy,
    }
    if args.json:
        _print_json(payload)
    else:
        print("SealDrop inspect")
        print("---------------")
        for key, value in payload.items():
            if key != "status":
                print(f"{key}: {value}")
    return EXIT_OK


def _render_signature_summary(checks: tuple) -> tuple[str, list[str]]:
    if not checks:
        return "unknown", ["- signatures: UNKNOWN (no signature checks requested)"]

    status_rank = {"pass": 0, "unknown": 1, "fail": 2}
    worst = max(checks, key=lambda item: status_rank.get(item.status, 2))
    overall = "PASS" if worst.status == "pass" else "FAIL" if worst.status == "fail" else "UNKNOWN"
    lines = [f"- signatures: {overall}"]
    for check in checks:
        lines.append(f"  - {check.signer}: {check.status.upper()} ({check.reason})")
    return overall.lower(), lines


def _cmd_verify(args: argparse.Namespace) -> int:
    passphrase = _resolve_passphrase(args, for_create=False)
    result = verify_package(Path(args.package_file), passphrase)

    signature_checks = None
    sig_overall = "unknown"
    if args.public_key:
        key_map = parse_public_key_mappings(args.public_key)
        sig_result = verify_signatures(
            package_path=Path(args.package_file),
            public_keys=key_map,
            signature_path=Path(args.signature_file) if args.signature_file else None,
        )
        signature_checks = sig_result.checks

    payload = {
        "status": "ok",
        "package_path": str(result.package_path),
        "package_sha256": result.package_sha256,
        "file_name": result.file_name,
        "file_size": result.file_size,
        "file_sha256": result.file_sha256,
        "created_utc": result.created_utc,
        "sender_note": result.metadata_note,
    }
    if signature_checks is not None:
        payload["signature_checks"] = [
            {"signer": item.signer, "status": item.status, "reason": item.reason}
            for item in signature_checks
        ]

    if args.json:
        _print_json(payload)
    else:
        print("SealDrop trust report")
        print("---------------------")
        print("- package integrity/authentication: PASS")
        print("- file_name:", result.file_name)
        print("- file_size:", result.file_size)
        print("- file_sha256:", result.file_sha256)
        print("- sealed_at:", result.created_utc)
        if signature_checks is None:
            print("- signatures: UNKNOWN (no signer keys provided)")
        else:
            sig_overall, sig_lines = _render_signature_summary(signature_checks)
            for line in sig_lines:
                print(line)
            if sig_overall == "fail":
                raise ConfigError("signature verification reported failures")
    return EXIT_OK


def _cmd_extract(args: argparse.Namespace) -> int:
    passphrase = _resolve_passphrase(args, for_create=False)
    destination = extract_package(
        package_path=Path(args.package_file),
        output_dir=Path(args.out_dir),
        passphrase=passphrase,
        overwrite=args.overwrite,
    )
    payload = {
        "status": "ok",
        "output_path": str(destination),
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"extracted: {destination}")
    return EXIT_OK


def _cmd_sign(args: argparse.Namespace) -> int:
    result = sign_package(
        package_path=Path(args.package_file),
        private_key_path=Path(args.private_key),
        signer=args.signer,
        signature_path=Path(args.signature_file) if args.signature_file else None,
    )
    payload = {
        "status": "ok",
        "signature_path": str(result.signature_path),
        "signer": result.signer,
        "package_sha256": result.package_sha256,
        "signatures_total": result.signatures_total,
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"signed: {result.signature_path}")
        print(f"signer: {result.signer}")
        print(f"package_sha256: {result.package_sha256}")
        print(f"signatures_total: {result.signatures_total}")
    return EXIT_OK


def _add_seal_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    seal = subparsers.add_parser("seal", help="seal file into encrypted .sdpkg package")
    seal.add_argument("input_file", help="input file path")
    seal.add_argument("-o", "--out", dest="output_package", help="output package path (defaults to <file>.sdpkg)")
    seal.add_argument("--note", default="", help="optional note stored inside encrypted metadata")
    seal.add_argument("--scrypt-n", type=int, default=2**15, help="scrypt N parameter")
    seal.add_argument("--scrypt-r", type=int, default=8, help="scrypt r parameter")
    seal.add_argument("--scrypt-p", type=int, default=1, help="scrypt p parameter")
    seal.add_argument("--deterministic", action="store_true", help="deterministic package bytes for reproducible artifacts")
    seal.add_argument("--json", action="store_true", help="output machine-readable JSON")
    _add_passphrase_args(seal)
    seal.set_defaults(handler=_cmd_seal)


def _add_inspect_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    inspect_p = subparsers.add_parser("inspect", help="inspect package header without decryption")
    inspect_p.add_argument("package_file", help="package path")
    inspect_p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    inspect_p.set_defaults(handler=_cmd_inspect)


def _add_verify_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    verify_p = subparsers.add_parser("verify", help="verify package authentication/integrity (and optional signatures)")
    verify_p.add_argument("package_file", help="package path")
    verify_p.add_argument("--public-key", action="append", default=[], help="signer public key mapping signer=path")
    verify_p.add_argument("--signature-file", help="signature sidecar path (default: <package>.sig.json)")
    verify_p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    _add_passphrase_args(verify_p)
    verify_p.set_defaults(handler=_cmd_verify)


def _add_extract_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    extract_p = subparsers.add_parser("extract", help="verify + decrypt + write output file")
    extract_p.add_argument("package_file", help="package path")
    extract_p.add_argument("--out-dir", default=".", help="destination directory (default: current directory)")
    extract_p.add_argument("--overwrite", action="store_true", help="allow overwriting destination file")
    extract_p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    _add_passphrase_args(extract_p)
    extract_p.set_defaults(handler=_cmd_extract)


def _add_sign_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    sign_p = subparsers.add_parser("sign", help="add Ed25519 signature to package sidecar")
    sign_p.add_argument("package_file", help="package path")
    sign_p.add_argument("--private-key", required=True, help="Ed25519 private key path (PEM)")
    sign_p.add_argument("--signer", required=True, help="signer identity label (example: alice)")
    sign_p.add_argument("--signature-file", help="signature sidecar path (default: <package>.sig.json)")
    sign_p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    sign_p.set_defaults(handler=_cmd_sign)


def _add_package_compat_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Backward-compatible package subcommands from early prototype builds."""
    package = subparsers.add_parser("package", help="(compat) package create/inspect/verify/extract")
    pkg_sub = package.add_subparsers(dest="pkg_cmd", required=True)

    create_p = pkg_sub.add_parser("create", help="(compat) create encrypted .sdpkg package")
    create_p.add_argument("--in", dest="input_file", required=True, help="input file path")
    create_p.add_argument("--out", dest="output_package", required=True, help="output package path")
    create_p.add_argument("--note", default="", help="optional note stored inside encrypted metadata")
    create_p.add_argument("--scrypt-n", type=int, default=2**15, help="scrypt N parameter")
    create_p.add_argument("--scrypt-r", type=int, default=8, help="scrypt r parameter")
    create_p.add_argument("--scrypt-p", type=int, default=1, help="scrypt p parameter")
    create_p.add_argument("--deterministic", action="store_true", help="deterministic package bytes for reproducible artifacts")
    create_p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    _add_passphrase_args(create_p)
    create_p.set_defaults(handler=_cmd_seal)

    inspect_p = pkg_sub.add_parser("inspect", help="(compat) inspect package header")
    inspect_p.add_argument("--in", dest="package_file", required=True, help="package path")
    inspect_p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    inspect_p.set_defaults(handler=_cmd_inspect)

    verify_p = pkg_sub.add_parser("verify", help="(compat) verify package")
    verify_p.add_argument("--in", dest="package_file", required=True, help="package path")
    verify_p.add_argument("--public-key", action="append", default=[], help="signer public key mapping signer=path")
    verify_p.add_argument("--signature-file", help="signature sidecar path")
    verify_p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    _add_passphrase_args(verify_p)
    verify_p.set_defaults(handler=_cmd_verify)

    extract_p = pkg_sub.add_parser("extract", help="(compat) extract package")
    extract_p.add_argument("--in", dest="package_file", required=True, help="package path")
    extract_p.add_argument("--out-dir", dest="out_dir", required=True, help="destination directory")
    extract_p.add_argument("--overwrite", action="store_true", help="allow overwrite")
    extract_p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    _add_passphrase_args(extract_p)
    extract_p.set_defaults(handler=_cmd_extract)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sealdrop",
        description="SealDrop: secure file packaging for verifiable encrypted transfer.",
    )
    subparsers = parser.add_subparsers(dest="top_cmd", required=True)

    _add_seal_parser(subparsers)
    _add_verify_parser(subparsers)
    _add_inspect_parser(subparsers)
    _add_extract_parser(subparsers)
    _add_sign_parser(subparsers)

    keygen = subparsers.add_parser("keygen", help="generate random bytes for manual workflows")
    keygen.add_argument("--bytes", type=int, default=32, help="number of random bytes (default: 32)")
    keygen.add_argument("--json", action="store_true", help="output machine-readable JSON")
    keygen.set_defaults(handler=_cmd_keygen)

    _add_package_compat_parser(subparsers)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except AuthenticationError:
        print("ERROR: package authentication failed.", file=sys.stderr)
        return EXIT_AUTH
    except PackageFormatError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_FORMAT
    except SafetyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_SAFETY
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_CONFIG


if __name__ == "__main__":
    raise SystemExit(main())
