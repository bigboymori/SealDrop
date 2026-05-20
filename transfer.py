
"""Transfer/session helpers for SealDrop artifacts.

SealDrop v1 is package-centric and transport-agnostic. This module keeps
transport metadata separate so CLI and future wrappers can reason about
handoff state without expanding into chat or sync semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .package import PackageBuildResult


@dataclass(frozen=True)
class TransferArtifact:
    package_path: Path
    package_sha256: str
    package_size: int
    created_utc: str
    expires_utc: str | None


def _parse_utc(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def build_transfer_artifact(
    package_result: PackageBuildResult,
    *,
    ttl_seconds: int | None = None,
) -> TransferArtifact:
    expires_utc: str | None = None
    if ttl_seconds is not None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        created = _parse_utc(package_result.created_utc)
        expires = created + timedelta(seconds=ttl_seconds)
        expires_utc = expires.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    return TransferArtifact(
        package_path=package_result.package_path,
        package_sha256=package_result.package_sha256,
        package_size=package_result.package_size,
        created_utc=package_result.created_utc,
        expires_utc=expires_utc,
    )


def artifact_is_expired(artifact: TransferArtifact, now_utc: datetime | None = None) -> bool:
    if artifact.expires_utc is None:
        return False
    now = now_utc or datetime.now(timezone.utc)
    return now >= _parse_utc(artifact.expires_utc)
