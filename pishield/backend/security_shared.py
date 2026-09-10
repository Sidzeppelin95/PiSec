"""Shared security primitives used by wallet and security services."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256


def utc_now() -> datetime:
    """Return a timezone-aware timestamp in UTC."""
    return datetime.now(timezone.utc)


def normalize_utc(value: datetime | None) -> datetime | None:
    """Normalize a persisted timestamp to an aware UTC datetime."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass
class Wallet:
    """Shared wallet state used by authentication and recovery services."""

    username: str
    active_passphrase_hash: str
    created_at: datetime = field(default_factory=utc_now)
    revoked_passphrase_hashes: set[str] = field(default_factory=set)
    recovery_locked_until: datetime | None = None

    def __post_init__(self) -> None:
        self.created_at = normalize_utc(self.created_at)
        self.recovery_locked_until = normalize_utc(self.recovery_locked_until)


class SecurityUtils:
    """Stateless helpers shared across security components."""

    @staticmethod
    def hash_passphrase(passphrase: str) -> str:
        return sha256(passphrase.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ConnectionMetadata:
    """Connection facts supplied by the caller rather than encoded in an ID."""

    ip_address: str | None = None
    uses_vpn: bool = False
    uses_tor: bool = False
