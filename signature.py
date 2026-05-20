"""Detached package signatures for SealDrop artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypto import b64d, b64e, canonical_json_bytes, sha256_hex
from .errors import ConfigError, PackageFormatError

SIGNATURE_FILE_SUFFIX = ".sig.json"
SIGNATURE_FORMAT = "sdpkg-signatures"
SIGNATURE_VERSION = 1


@dataclass(frozen=True)
class SignatureResult:
    signature_path: Path
    signer: str
    package_sha256: str
    signatures_total: int


@dataclass(frozen=True)
class SignatureRecord:
    signer: str
    signed_utc: str
    package_sha256: str
    signature_b64: str


@dataclass(frozen=True)
class SignatureCheck:
    signer: str
    status: str
    reason: str


@dataclass(frozen=True)
class SignatureVerifyResult:
    signature_path: Path
    package_sha256: str
    checks: tuple[SignatureCheck, ...]


@dataclass(frozen=True)
class SignatureInspectResult:
    signature_path: Path
    package_sha256: str
    records: tuple[SignatureRecord, ...]


def _utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_signature_path(package_path: Path) -> Path:
    return package_path.with_name(package_path.name + SIGNATURE_FILE_SUFFIX)


def _signature_message(package_sha256_hex: str) -> bytes:
    if len(package_sha256_hex) != 64:
        raise ConfigError("package digest must be 64 hex chars")
    try:
        digest_bytes = bytes.fromhex(package_sha256_hex)
    except ValueError as exc:
        raise ConfigError("package digest must be valid hex") from exc
    return b"sealdrop-signature-v1:" + digest_bytes


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigError("private key must be Ed25519 PEM")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ConfigError("public key must be Ed25519 PEM")
    return key


def _validate_signature_payload(payload: dict) -> None:
    if payload.get("format") != SIGNATURE_FORMAT or payload.get("version") != SIGNATURE_VERSION:
        raise PackageFormatError("unsupported signature format/version")
    signatures = payload.get("signatures")
    if not isinstance(signatures, list):
        raise PackageFormatError("signature payload is malformed")


def _load_signatures(path: Path) -> dict:
    if not path.exists():
        return {
            "format": SIGNATURE_FORMAT,
            "version": SIGNATURE_VERSION,
            "package_name": "",
            "package_sha256": "",
            "signatures": [],
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PackageFormatError("signature sidecar is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise PackageFormatError("signature sidecar must be a JSON object")
    _validate_signature_payload(payload)
    return payload


def _save_signatures(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sign_package(
    package_path: Path,
    private_key_path: Path,
    signer: str,
    *,
    signature_path: Path | None = None,
) -> SignatureResult:
    if not signer or any(ch.isspace() for ch in signer):
        raise ConfigError("signer id must be non-empty and contain no whitespace")

    pkg_sha = sha256_hex(package_path.read_bytes())
    message = _signature_message(pkg_sha)
    private_key = _load_private_key(private_key_path)
    signature = private_key.sign(message)

    sidecar_path = signature_path or default_signature_path(package_path)
    payload = _load_signatures(sidecar_path)

    existing_digest = payload.get("package_sha256") or ""
    if existing_digest and existing_digest != pkg_sha:
        raise ConfigError("signature sidecar belongs to a different package digest")

    payload["package_name"] = package_path.name
    payload["package_sha256"] = pkg_sha
    signatures = payload.setdefault("signatures", [])
    signatures.append(
        {
            "signer": signer,
            "signed_utc": _utc_now_rfc3339(),
            "package_sha256": pkg_sha,
            "signature_b64": b64e(signature),
        }
    )

    _save_signatures(sidecar_path, payload)
    return SignatureResult(
        signature_path=sidecar_path,
        signer=signer,
        package_sha256=pkg_sha,
        signatures_total=len(signatures),
    )


def verify_signatures(
    package_path: Path,
    public_keys: dict[str, Path],
    *,
    signature_path: Path | None = None,
) -> SignatureVerifyResult:
    if not public_keys:
        raise ConfigError("at least one signer public key is required")

    pkg_sha = sha256_hex(package_path.read_bytes())
    sidecar_path = signature_path or default_signature_path(package_path)
    payload = _load_signatures(sidecar_path)
    _validate_signature_payload(payload)

    sidecar_sha = payload.get("package_sha256")
    if not isinstance(sidecar_sha, str) or len(sidecar_sha) != 64:
        raise PackageFormatError("signature sidecar package digest is invalid")

    checks: list[SignatureCheck] = []
    if sidecar_sha != pkg_sha:
        checks.append(
            SignatureCheck(
                signer="<sidecar>",
                status="fail",
                reason="sidecar package digest does not match package",
            )
        )

    signatures = payload.get("signatures", [])
    message = _signature_message(pkg_sha)

    for raw in signatures:
        if not isinstance(raw, dict):
            checks.append(SignatureCheck(signer="<unknown>", status="fail", reason="malformed signature record"))
            continue

        signer = raw.get("signer")
        sig_b64 = raw.get("signature_b64")
        record_sha = raw.get("package_sha256")

        if not isinstance(signer, str) or not signer:
            checks.append(SignatureCheck(signer="<unknown>", status="fail", reason="missing signer id"))
            continue
        if record_sha != pkg_sha:
            checks.append(SignatureCheck(signer=signer, status="fail", reason="signature record digest mismatch"))
            continue
        if signer not in public_keys:
            checks.append(SignatureCheck(signer=signer, status="unknown", reason="no public key provided"))
            continue
        if not isinstance(sig_b64, str):
            checks.append(SignatureCheck(signer=signer, status="fail", reason="missing signature payload"))
            continue

        public_key = _load_public_key(public_keys[signer])
        try:
            public_key.verify(b64d(sig_b64), message)
            checks.append(SignatureCheck(signer=signer, status="pass", reason="signature valid"))
        except (InvalidSignature, ValueError):
            checks.append(SignatureCheck(signer=signer, status="fail", reason="signature invalid"))

    if not signatures:
        checks.append(SignatureCheck(signer="<none>", status="unknown", reason="no signatures present"))

    return SignatureVerifyResult(
        signature_path=sidecar_path,
        package_sha256=pkg_sha,
        checks=tuple(checks),
    )


def parse_public_key_mappings(raw_values: Iterable[str]) -> dict[str, Path]:
    mappings: dict[str, Path] = {}
    for value in raw_values:
        if "=" not in value:
            raise ConfigError("public key mapping must use signer=path format")
        signer, path_str = value.split("=", 1)
        signer = signer.strip()
        if not signer:
            raise ConfigError("public key mapping signer is empty")
        path = Path(path_str.strip())
        if not path.exists():
            raise ConfigError(f"public key not found for signer '{signer}': {path}")
        mappings[signer] = path
    return mappings


def inspect_signatures(
    package_path: Path,
    *,
    signature_path: Path | None = None,
) -> SignatureInspectResult:
    sidecar_path = signature_path or default_signature_path(package_path)
    if not sidecar_path.exists():
        return SignatureInspectResult(
            signature_path=sidecar_path,
            package_sha256=sha256_hex(package_path.read_bytes()),
            records=tuple(),
        )

    payload = _load_signatures(sidecar_path)
    _validate_signature_payload(payload)
    records: list[SignatureRecord] = []
    for raw in payload.get("signatures", []):
        if not isinstance(raw, dict):
            continue
        signer = raw.get("signer")
        signed_utc = raw.get("signed_utc")
        package_sha = raw.get("package_sha256")
        signature_b64 = raw.get("signature_b64")
        if not isinstance(signer, str) or not signer:
            continue
        if not isinstance(signed_utc, str):
            continue
        if not isinstance(package_sha, str) or len(package_sha) != 64:
            continue
        if not isinstance(signature_b64, str):
            continue
        records.append(
            SignatureRecord(
                signer=signer,
                signed_utc=signed_utc,
                package_sha256=package_sha,
                signature_b64=signature_b64,
            )
        )

    package_sha = payload.get("package_sha256")
    if not isinstance(package_sha, str):
        package_sha = ""
    return SignatureInspectResult(
        signature_path=sidecar_path,
        package_sha256=package_sha,
        records=tuple(records),
    )
