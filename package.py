
"""SealDrop package creation, inspection, verification, and extraction."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import (
    AES_GCM_NONCE_BYTES,
    CIPHER_NAME,
    HEADER_LENGTH_BYTES,
    KDF_NAME,
    KDF_SALT_BYTES,
    MAX_HEADER_BYTES,
    MAX_INPUT_FILE_BYTES,
    MAX_PAYLOAD_METADATA_BYTES,
    MAX_VISIBLE_NOTE_BYTES,
    PACKAGE_EXTENSION,
    PACKAGE_FORMAT_NAME,
    PACKAGE_MAGIC,
    PACKAGE_VERSION,
    PAYLOAD_META_LENGTH_BYTES,
    PAYLOAD_SCHEMA_VERSION,
)
from .crypto import (
    ScryptParams,
    b64d,
    b64e,
    canonical_json_bytes,
    constant_time_eq_hex,
    decrypt_aes_gcm,
    derive_key_scrypt,
    encrypt_aes_gcm,
    secure_random_bytes,
    sha256_hex,
)
from .errors import AuthenticationError, ConfigError, PackageFormatError, SafetyError

AEAD_GCM_TAG_BYTES = 16


@dataclass(frozen=True)
class PackageBuildResult:
    package_path: Path
    package_sha256: str
    package_size: int
    file_sha256: str
    file_size: int
    created_utc: str


@dataclass(frozen=True)
class PackageVerifyResult:
    package_path: Path
    package_sha256: str
    file_name: str
    file_size: int
    file_sha256: str
    created_utc: str
    metadata_note: str


@dataclass(frozen=True)
class PackageInspectResult:
    package_path: Path
    package_sha256: str
    package_size: int
    format: str
    version: int
    created_utc: str
    cipher: str
    kdf: str
    ciphertext_len: int
    metadata_policy: str


def _utc_now_rfc3339() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _deterministic_timestamp() -> str:
    # Reproducible packages need a stable timestamp field.
    return "1970-01-01T00:00:00Z"


def _coerce_passphrase_bytes(passphrase: str | bytes | bytearray) -> bytes:
    if isinstance(passphrase, str):
        return passphrase.encode("utf-8")
    if isinstance(passphrase, (bytes, bytearray)):
        return bytes(passphrase)
    raise ConfigError("passphrase must be text or bytes")


def _derive_deterministic_bytes(
    *,
    passphrase: str | bytes | bytearray,
    file_sha256_hex: str,
    label: bytes,
    count: int,
) -> bytes:
    seed = hashlib.sha256()
    seed.update(b"sealdrop-deterministic-v1")
    seed.update(label)
    seed.update(_coerce_passphrase_bytes(passphrase))
    seed.update(file_sha256_hex.encode("ascii"))
    digest = seed.digest()
    if count <= len(digest):
        return digest[:count]
    # Small deterministic expander for future count growth needs.
    out = bytearray()
    counter = 0
    while len(out) < count:
        block = hashlib.sha256(digest + counter.to_bytes(4, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:count])


def _validate_input_file(path: Path, max_file_bytes: int) -> None:
    if not path.exists() or not path.is_file():
        raise ConfigError(f"input file not found: {path}")
    size = path.stat().st_size
    if size < 0:
        raise ConfigError("input file size is invalid")
    if size > max_file_bytes:
        raise ConfigError(
            f"input file exceeds maximum allowed bytes ({size} > {max_file_bytes})"
        )


def _validate_filename_for_extract(name: str) -> str:
    if not isinstance(name, str):
        raise SafetyError("invalid output filename")
    if not name or name in {".", ".."}:
        raise SafetyError("invalid output filename")
    if any(ord(ch) < 32 for ch in name):
        raise SafetyError("output filename contains control characters")
    if "/" in name or "\\" in name:
        raise SafetyError("output filename must not include path separators")
    if ":" in name:
        raise SafetyError("output filename must not include drive delimiters")
    if len(name.encode("utf-8")) > 255:
        raise SafetyError("output filename is too long")
    return name


def _validate_note(note: str | None) -> str:
    if note is None:
        return ""
    note = str(note).strip()
    if len(note.encode("utf-8")) > MAX_VISIBLE_NOTE_BYTES:
        raise ConfigError(
            f"visible note exceeds {MAX_VISIBLE_NOTE_BYTES} UTF-8 bytes"
        )
    if any(ord(ch) < 32 and ch not in {9, 10, 13} for ch in note):
        raise ConfigError("visible note contains unsupported control characters")
    return note


def _encode_payload(metadata: dict[str, Any], file_bytes: bytes) -> bytes:
    meta_bytes = canonical_json_bytes(metadata)
    if len(meta_bytes) > MAX_PAYLOAD_METADATA_BYTES:
        raise ConfigError("encrypted metadata is too large")
    meta_len = len(meta_bytes).to_bytes(PAYLOAD_META_LENGTH_BYTES, "big")
    return meta_len + meta_bytes + file_bytes


def _decode_payload(payload: bytes) -> tuple[dict[str, Any], bytes]:
    if len(payload) < PAYLOAD_META_LENGTH_BYTES:
        raise PackageFormatError("decrypted payload is malformed")
    meta_len = int.from_bytes(payload[:PAYLOAD_META_LENGTH_BYTES], "big")
    if meta_len <= 0 or meta_len > MAX_PAYLOAD_METADATA_BYTES:
        raise PackageFormatError("decrypted metadata length is invalid")
    meta_start = PAYLOAD_META_LENGTH_BYTES
    meta_end = meta_start + meta_len
    if meta_end > len(payload):
        raise PackageFormatError("decrypted payload is truncated")
    try:
        metadata = json.loads(payload[meta_start:meta_end].decode("utf-8"))
    except Exception as exc:
        raise PackageFormatError("decrypted metadata is invalid") from exc
    if not isinstance(metadata, dict):
        raise PackageFormatError("decrypted metadata structure is invalid")
    file_bytes = payload[meta_end:]
    return metadata, file_bytes


def _validate_payload_metadata(metadata: dict[str, Any], file_bytes: bytes) -> tuple[str, int, str, str]:
    if metadata.get("payload_schema_version") != PAYLOAD_SCHEMA_VERSION:
        raise PackageFormatError("unsupported payload schema version")
    file_name = metadata.get("file_name")
    file_size = metadata.get("file_size")
    file_sha256 = metadata.get("file_sha256")
    sealed_at_utc = metadata.get("sealed_at_utc")

    if not isinstance(file_name, str) or not file_name:
        raise PackageFormatError("payload file_name is invalid")
    if not isinstance(file_size, int) or file_size < 0:
        raise PackageFormatError("payload file_size is invalid")
    if not isinstance(file_sha256, str) or len(file_sha256) != 64:
        raise PackageFormatError("payload file_sha256 is invalid")
    if not isinstance(sealed_at_utc, str) or not sealed_at_utc:
        raise PackageFormatError("payload sealed_at_utc is invalid")

    if file_size != len(file_bytes):
        raise PackageFormatError("payload file_size mismatch")
    actual_sha = sha256_hex(file_bytes)
    if not constant_time_eq_hex(actual_sha, file_sha256):
        raise PackageFormatError("payload integrity mismatch")
    return file_name, file_size, file_sha256, sealed_at_utc


def _encode_header(header: dict[str, Any]) -> bytes:
    header_bytes = canonical_json_bytes(header)
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise ConfigError("package header is too large")
    return header_bytes


def _decode_header(header_bytes: bytes) -> dict[str, Any]:
    try:
        raw = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise PackageFormatError("package header is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise PackageFormatError("package header must be a JSON object")
    canonical_bytes = canonical_json_bytes(raw)
    if not canonical_bytes == header_bytes:
        raise PackageFormatError("package header must use canonical JSON encoding")

    required = {
        "format",
        "version",
        "created_utc",
        "cipher",
        "kdf",
        "ciphertext_len",
        "metadata_policy",
    }
    missing = required - set(raw.keys())
    if missing:
        raise PackageFormatError("package header missing required fields")

    if raw.get("format") != PACKAGE_FORMAT_NAME or raw.get("version") != PACKAGE_VERSION:
        raise PackageFormatError("unsupported package format/version")
    if not isinstance(raw.get("created_utc"), str):
        raise PackageFormatError("header created_utc is invalid")
    if not isinstance(raw.get("metadata_policy"), str):
        raise PackageFormatError("header metadata_policy is invalid")

    cipher = raw.get("cipher")
    if not isinstance(cipher, dict):
        raise PackageFormatError("header cipher is invalid")
    if cipher.get("name") != CIPHER_NAME:
        raise PackageFormatError("unsupported cipher")
    nonce_b64 = cipher.get("nonce_b64")
    if not isinstance(nonce_b64, str):
        raise PackageFormatError("header nonce is invalid")
    nonce = b64d(nonce_b64)
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise PackageFormatError("header nonce length is invalid")

    kdf = raw.get("kdf")
    if not isinstance(kdf, dict):
        raise PackageFormatError("header kdf is invalid")
    if kdf.get("name") != KDF_NAME:
        raise PackageFormatError("unsupported kdf")
    salt_b64 = kdf.get("salt_b64")
    if not isinstance(salt_b64, str):
        raise PackageFormatError("header salt is invalid")
    salt = b64d(salt_b64)
    if len(salt) != KDF_SALT_BYTES:
        raise PackageFormatError("header salt length is invalid")

    for key_name in ("n", "r", "p"):
        if not isinstance(kdf.get(key_name), int):
            raise PackageFormatError("header kdf parameters are invalid")

    ciphertext_len = raw.get("ciphertext_len")
    if not isinstance(ciphertext_len, int) or ciphertext_len < 16:
        raise PackageFormatError("header ciphertext length is invalid")

    return raw


def _parse_package_with_header_bytes(blob: bytes) -> tuple[dict[str, Any], bytes, bytes]:
    if len(blob) < len(PACKAGE_MAGIC) + HEADER_LENGTH_BYTES:
        raise PackageFormatError("package is too small")
    if not blob.startswith(PACKAGE_MAGIC):
        raise PackageFormatError("unsupported package magic")

    header_len_start = len(PACKAGE_MAGIC)
    header_len_end = header_len_start + HEADER_LENGTH_BYTES
    header_len = int.from_bytes(blob[header_len_start:header_len_end], "big")
    if header_len <= 0 or header_len > MAX_HEADER_BYTES:
        raise PackageFormatError("header length is invalid")

    header_start = header_len_end
    header_end = header_start + header_len
    if header_end > len(blob):
        raise PackageFormatError("package header exceeds file length")

    header_bytes = blob[header_start:header_end]
    header = _decode_header(header_bytes)
    ciphertext = blob[header_end:]
    if len(ciphertext) != header["ciphertext_len"]:
        raise PackageFormatError("ciphertext length mismatch")

    return header, header_bytes, ciphertext


def _parse_package_bytes(blob: bytes) -> tuple[dict[str, Any], bytes]:
    header, _, ciphertext = _parse_package_with_header_bytes(blob)
    return header, ciphertext


def inspect_package(package_path: Path) -> PackageInspectResult:
    blob = package_path.read_bytes()
    header, _, ciphertext = _parse_package_with_header_bytes(blob)
    return PackageInspectResult(
        package_path=package_path,
        package_sha256=sha256_hex(blob),
        package_size=len(blob),
        format=header["format"],
        version=header["version"],
        created_utc=header["created_utc"],
        cipher=header["cipher"]["name"],
        kdf=header["kdf"]["name"],
        ciphertext_len=len(ciphertext),
        metadata_policy=header["metadata_policy"],
    )


def create_package(
    input_path: Path,
    output_path: Path,
    passphrase: str | bytes | bytearray,
    *,
    note: str | None = None,
    scrypt_params: ScryptParams | None = None,
    max_file_bytes: int = MAX_INPUT_FILE_BYTES,
    deterministic: bool = False,
) -> PackageBuildResult:
    _validate_input_file(input_path, max_file_bytes)
    note = _validate_note(note)
    file_bytes = input_path.read_bytes()
    file_sha = sha256_hex(file_bytes)
    created_utc = _deterministic_timestamp() if deterministic else _utc_now_rfc3339()

    payload_meta = {
        "payload_schema_version": PAYLOAD_SCHEMA_VERSION,
        "file_name": input_path.name,
        "file_size": len(file_bytes),
        "file_sha256": file_sha,
        "sealed_at_utc": created_utc,
        "sender_note": note,
    }
    payload = _encode_payload(payload_meta, file_bytes)

    if deterministic:
        salt = _derive_deterministic_bytes(
            passphrase=passphrase,
            file_sha256_hex=file_sha,
            label=b"salt",
            count=KDF_SALT_BYTES,
        )
        nonce = _derive_deterministic_bytes(
            passphrase=passphrase,
            file_sha256_hex=file_sha,
            label=b"nonce",
            count=AES_GCM_NONCE_BYTES,
        )
    else:
        salt = secure_random_bytes(KDF_SALT_BYTES)
        nonce = secure_random_bytes(AES_GCM_NONCE_BYTES)
    params = scrypt_params or ScryptParams()
    key = derive_key_scrypt(passphrase=passphrase, salt=salt, params=params)
    ciphertext_len = len(payload) + AEAD_GCM_TAG_BYTES

    header = {
        "format": PACKAGE_FORMAT_NAME,
        "version": PACKAGE_VERSION,
        "created_utc": created_utc,
        "cipher": {
            "name": CIPHER_NAME,
            "nonce_b64": b64e(nonce),
        },
        "kdf": {
            "name": KDF_NAME,
            "salt_b64": b64e(salt),
            "n": params.n,
            "r": params.r,
            "p": params.p,
        },
        "ciphertext_len": ciphertext_len,
        "metadata_policy": (
            "Package size, creation time, and KDF/cipher parameters are visible. "
            "File name, note, file size, and file content stay inside encrypted payload."
        ),
    }
    header_bytes = _encode_header(header)
    ciphertext = encrypt_aes_gcm(key=key, nonce=nonce, plaintext=payload, aad=header_bytes)
    if len(ciphertext) != ciphertext_len:
        raise ConfigError("internal ciphertext length mismatch")
    package_bytes = (
        PACKAGE_MAGIC
        + len(header_bytes).to_bytes(HEADER_LENGTH_BYTES, "big")
        + header_bytes
        + ciphertext
    )

    if not output_path.name.lower().endswith(PACKAGE_EXTENSION):
        output_path = output_path.with_name(output_path.name + PACKAGE_EXTENSION)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(package_bytes)

    return PackageBuildResult(
        package_path=output_path,
        package_sha256=sha256_hex(package_bytes),
        package_size=len(package_bytes),
        file_sha256=file_sha,
        file_size=len(file_bytes),
        created_utc=created_utc,
    )


def verify_package(
    package_path: Path,
    passphrase: str | bytes | bytearray,
) -> PackageVerifyResult:
    blob = package_path.read_bytes()
    header, header_bytes, ciphertext = _parse_package_with_header_bytes(blob)

    nonce = b64d(header["cipher"]["nonce_b64"])
    salt = b64d(header["kdf"]["salt_b64"])
    params = ScryptParams(
        n=header["kdf"]["n"],
        r=header["kdf"]["r"],
        p=header["kdf"]["p"],
    )

    key = derive_key_scrypt(passphrase=passphrase, salt=salt, params=params)

    try:
        payload = decrypt_aes_gcm(
            key=key,
            nonce=nonce,
            ciphertext=ciphertext,
            aad=header_bytes,
        )
        meta, file_bytes = _decode_payload(payload)
        file_name, file_size, file_sha, sealed_at_utc = _validate_payload_metadata(
            meta,
            file_bytes,
        )
    except AuthenticationError:
        raise
    except PackageFormatError:
        raise
    except Exception as exc:
        # Keep decryption+validation failures uniform for callers.
        raise PackageFormatError("package verification failed") from exc

    return PackageVerifyResult(
        package_path=package_path,
        package_sha256=sha256_hex(blob),
        file_name=file_name,
        file_size=file_size,
        file_sha256=file_sha,
        created_utc=sealed_at_utc,
        metadata_note=str(meta.get("sender_note") or ""),
    )


def extract_package(
    package_path: Path,
    output_dir: Path,
    passphrase: str | bytes | bytearray,
    *,
    overwrite: bool = False,
) -> Path:
    verified = verify_package(package_path=package_path, passphrase=passphrase)
    blob = package_path.read_bytes()
    header, header_bytes, ciphertext = _parse_package_with_header_bytes(blob)
    nonce = b64d(header["cipher"]["nonce_b64"])
    salt = b64d(header["kdf"]["salt_b64"])
    params = ScryptParams(
        n=header["kdf"]["n"],
        r=header["kdf"]["r"],
        p=header["kdf"]["p"],
    )
    key = derive_key_scrypt(passphrase=passphrase, salt=salt, params=params)
    payload = decrypt_aes_gcm(
        key=key,
        nonce=nonce,
        ciphertext=ciphertext,
        aad=header_bytes,
    )
    meta, file_bytes = _decode_payload(payload)
    file_name, _, _, _ = _validate_payload_metadata(meta, file_bytes)

    safe_name = _validate_filename_for_extract(file_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / safe_name
    if destination.exists() and not overwrite:
        raise SafetyError(f"destination exists: {destination}")

    tmp_path = destination.with_name(destination.name + ".tmp")
    if tmp_path.exists():
        tmp_path.unlink()
    tmp_path.write_bytes(file_bytes)
    os.replace(tmp_path, destination)

    # Sanity check on final output to avoid silent truncation issues.
    if destination.stat().st_size != verified.file_size:
        raise SafetyError("extracted file size mismatch after write")
    return destination
