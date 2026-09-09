"""Wallet authentication and device helpers for the PiShield sandbox demo."""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Protocol

try:
    from .security_shared import SecurityUtils, Wallet, utc_now
except ImportError:  # Supports running the backend as a script.
    from security_shared import SecurityUtils, Wallet, utc_now


class RecoveryResponseHandler(Protocol):
    """The narrow interface wallet authentication needs from a security service."""

    def trigger_response(self, wallet: "Wallet") -> None: ...


@dataclass
class PiWalletManager:
    """In-memory wallet store with lock-aware passphrase authentication."""

    wallets: dict[str, Wallet] = field(default_factory=dict)
    response_handler: RecoveryResponseHandler | None = None

    def create_wallet(self, username: str, passphrase: str) -> Wallet:
        wallet = Wallet(
            username=username,
            active_passphrase_hash=SecurityUtils.hash_passphrase(passphrase),
        )
        self.wallets[username] = wallet
        return wallet

    def authenticate(self, username: str, entered_passphrase: str) -> bool:
        wallet = self.wallets.get(username)
        if wallet is None:
            raise ValueError("Wallet not found")

        # A recovery lock applies to every authentication attempt, including a
        # revoked passphrase, until its timezone-aware UTC expiry has passed.
        if wallet.recovery_locked_until and wallet.recovery_locked_until > utc_now():
            return False

        entered_hash = SecurityUtils.hash_passphrase(entered_passphrase)
        if entered_hash == wallet.active_passphrase_hash:
            return True

        if entered_hash in wallet.revoked_passphrase_hashes:
            if self.response_handler is not None:
                self.response_handler.trigger_response(wallet)
        return False


def build_device_fingerprint(user_agent: str, pi_username: str) -> str:
    """Return a stable demo fingerprint without storing raw browser details."""
    raw = f"{user_agent}|{pi_username}".encode("utf-8")
    return sha256(raw).hexdigest()[:24]
