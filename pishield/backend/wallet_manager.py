"""Wallet helpers for the PiShield sandbox demo."""

from __future__ import annotations

from hashlib import sha256


def build_device_fingerprint(user_agent: str, pi_username: str) -> str:
    """Return a stable demo fingerprint without storing raw browser details."""
    raw = f"{user_agent}|{pi_username}".encode("utf-8")
    return sha256(raw).hexdigest()[:24]
