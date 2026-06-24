"""PiShield wallet models and passphrase rotation/authentication workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import hashlib
import uuid


class SecurityUtils:
    """Shared helpers for wallet-security workflows."""

    @staticmethod
    def hash_passphrase(passphrase: str) -> str:
        """Hash a passphrase for demo storage.

        Production deployments should replace SHA-256 with a password hashing
        algorithm such as Argon2id and use per-passphrase salts.
        """

        return hashlib.sha256(passphrase.encode()).hexdigest()

    @staticmethod
    def generate_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def utc_now() -> datetime:
        return datetime.utcnow()


@dataclass
class PiDeviceProfile:
    """Known Pi Browser device profile for trust analysis."""

    device_id: str
    device_name: str
    operating_system: str
    pi_browser_verified: bool
    biometric_enabled: bool
    trusted_since: datetime
    last_active: datetime


@dataclass
class PiWallet:
    """Wallet state tracked by PiShield."""

    wallet_id: str
    pi_user_id: str
    active_passphrase_hash: str
    created_at: datetime = field(default_factory=SecurityUtils.utc_now)
    trusted_ips: List[str] = field(default_factory=list)
    trusted_devices: List[PiDeviceProfile] = field(default_factory=list)
    revoked_passphrase_hashes: List[str] = field(default_factory=list)
    recovery_locked_until: Optional[datetime] = None
    suspicious_attempt_count: int = 0


wallet_db: Dict[str, PiWallet] = {}


class PiWalletManager:
    """Creates wallets, rotates passphrases, and authenticates attempts."""

    @staticmethod
    def create_wallet(
        pi_user_id: str,
        passphrase: str,
        trusted_ip: str,
        device_profile: PiDeviceProfile,
    ) -> PiWallet:
        wallet = PiWallet(
            wallet_id=SecurityUtils.generate_id(),
            pi_user_id=pi_user_id,
            active_passphrase_hash=SecurityUtils.hash_passphrase(passphrase),
        )
        wallet.trusted_ips.append(trusted_ip)
        wallet.trusted_devices.append(device_profile)
        wallet_db[wallet.wallet_id] = wallet
        return wallet

    @staticmethod
    def rotate_passphrase(wallet_id: str, current_passphrase: str, new_passphrase: str) -> PiWallet:
        wallet = wallet_db.get(wallet_id)
        if not wallet:
            raise ValueError("Wallet not found")

        current_hash = SecurityUtils.hash_passphrase(current_passphrase)
        if current_hash != wallet.active_passphrase_hash:
            raise ValueError("Invalid active passphrase")

        wallet.revoked_passphrase_hashes.append(current_hash)
        wallet.active_passphrase_hash = SecurityUtils.hash_passphrase(new_passphrase)
        return wallet

    @staticmethod
    def authenticate(
        wallet_id: str,
        entered_passphrase: str,
        ip_address: str,
        device_id: str,
    ) -> bool:
        wallet = wallet_db.get(wallet_id)
        if not wallet:
            raise ValueError("Wallet not found")

        entered_hash = SecurityUtils.hash_passphrase(entered_passphrase)
        if entered_hash == wallet.active_passphrase_hash:
            return True

        if entered_hash in wallet.revoked_passphrase_hashes:
            from security_engine import PiSecurityEngine

            PiSecurityEngine.handle_old_passphrase_attempt(
                wallet=wallet,
                ip_address=ip_address,
                device_id=device_id,
            )
            return False

        return False
