
"""Cryptographic helpers for SealDrop.

SealDrop intentionally uses mature primitives from ``cryptography`` and avoids
custom cryptographic design.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .constants import (
    AES_GCM_NONCE_BYTES,
    AES_KEY_BYTES,
    KDF_DEFAULT_N,
    KDF_DEFAULT_P,
    KDF_DEFAULT_R,
    KDF_MAX_N,
    KDF_MAX_P,
    KDF_MAX_R,
    KDF_MIN_N,
    KDF_MIN_P,
    KDF_MIN_R,
    KDF_SALT_BYTES,
    MIN_PASSPHRASE_BYTES,
)
from .errors import AuthenticationError, ConfigError


@dataclass(frozen=True)
class ScryptParams:
    """Tunable scrypt parameters with bounded safety checks."""

    n: int = KDF_DEFAULT_N
    r: int = KDF_DEFAULT_R
    p: int = KDF_DEFAULT_P


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data.encode("ascii"))
    except Exception as exc:
        raise ConfigError("invalid base64 value") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def secure_random_bytes(count: int) -> bytes:
    if not isinstance(count, int) or count <= 0:
        raise ConfigError("random byte count must be a positive integer")
    return secrets.token_bytes(count)


def _validate_scrypt_params(params: ScryptParams) -> ScryptParams:
    if not isinstance(params.n, int) or params.n < KDF_MIN_N or params.n > KDF_MAX_N:
        raise ConfigError(f"scrypt n must be between {KDF_MIN_N} and {KDF_MAX_N}")
    if params.n & (params.n - 1):
        raise ConfigError("scrypt n must be a power of two")
    if not isinstance(params.r, int) or params.r < KDF_MIN_R or params.r > KDF_MAX_R:
        raise ConfigError(f"scrypt r must be between {KDF_MIN_R} and {KDF_MAX_R}")
    if not isinstance(params.p, int) or params.p < KDF_MIN_P or params.p > KDF_MAX_P:
        raise ConfigError(f"scrypt p must be between {KDF_MIN_P} and {KDF_MAX_P}")
    return params


def _coerce_passphrase(passphrase: str | bytes | bytearray) -> bytearray:
    if isinstance(passphrase, str):
        buf = bytearray(passphrase.encode("utf-8"))
    elif isinstance(passphrase, (bytes, bytearray)):
        buf = bytearray(passphrase)
    else:
        raise ConfigError("passphrase must be text or bytes")
    if len(buf) < MIN_PASSPHRASE_BYTES:
        raise ConfigError(f"passphrase must be at least {MIN_PASSPHRASE_BYTES} bytes")
    return buf


def best_effort_zeroize(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def derive_key_scrypt(
    passphrase: str | bytes | bytearray,
    salt: bytes,
    params: ScryptParams | None = None,
) -> bytes:
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != KDF_SALT_BYTES:
        raise ConfigError(f"salt must be {KDF_SALT_BYTES} bytes")
    params = _validate_scrypt_params(params or ScryptParams())
    passphrase_buf = _coerce_passphrase(passphrase)
    try:
        return Scrypt(
            salt=bytes(salt),
            length=AES_KEY_BYTES,
            n=params.n,
            r=params.r,
            p=params.p,
        ).derive(bytes(passphrase_buf))
    finally:
        best_effort_zeroize(passphrase_buf)


def encrypt_aes_gcm(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(key) != AES_KEY_BYTES:
        raise ConfigError("invalid key length")
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise ConfigError("invalid nonce length")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key) != AES_KEY_BYTES:
        raise ConfigError("invalid key length")
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise ConfigError("invalid nonce length")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise AuthenticationError("package authentication failed") from exc


def constant_time_eq_hex(left: str, right: str) -> bool:
    return hmac.compare_digest(left.lower(), right.lower())
