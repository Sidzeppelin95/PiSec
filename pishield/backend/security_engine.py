"""Demo security primitives for PiShield.

This module intentionally keeps state in memory because the project is a
sandbox demonstration. Production deployments should persist audit trails,
store only salted password hashes, validate Pi auth tokens server-side, and
separate sandbox/mainnet databases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from secrets import token_hex
from typing import Any


@dataclass
class RotationRecord:
    username: str
    device_fingerprint: str
    rotated_at: str
    old_passphrase_hash: str
    new_passphrase_hash: str
    biometric_confirmed: bool
    mfa_challenge_id: str
    pi_auth_uid: str | None = None


@dataclass
class SecurityEngine:
    rotations: list[RotationRecord] = field(default_factory=list)
    revoked_passphrases: set[str] = field(default_factory=set)
    suspicious_events: list[dict[str, Any]] = field(default_factory=list)
    mfa_challenges: dict[str, dict[str, Any]] = field(default_factory=dict)

    def create_mfa_challenge(
        self,
        username: str,
        pi_auth_uid: str | None = None,
    ) -> dict[str, Any]:
        challenge_id = token_hex(8)
        bound_pi_auth_uid = (
            pi_auth_uid.strip()
            if isinstance(pi_auth_uid, str) and pi_auth_uid.strip()
            else None
        )
        challenge = {
            "challenge_id": challenge_id,
            "username": username,
            "pi_auth_uid": bound_pi_auth_uid,
            "type": "biometric_confirmation",
            "status": "pending",
            "created_at": self._now(),
            "message": "Confirm biometric prompt in Pi Browser before rotating passphrase.",
        }
        self.mfa_challenges[challenge_id] = challenge
        return challenge

    def rotate_passphrase(
        self,
        *,
        username: str,
        current_passphrase: str,
        new_passphrase: str,
        biometric_confirmed: bool,
        device_fingerprint: str,
        mfa_challenge_id: str | None = None,
        pi_auth_uid: str | None = None,
    ) -> tuple[dict[str, Any], int]:
        if not username or not current_passphrase or not new_passphrase:
            return {"error": "username, current_passphrase, and new_passphrase are required"}, 400

        if len(new_passphrase) < 12:
            return {"error": "new_passphrase must be at least 12 characters"}, 400

        if current_passphrase == new_passphrase:
            self._flag(username, device_fingerprint, "passphrase_reuse_attempt", pi_auth_uid=pi_auth_uid)
            return {"error": "new_passphrase must be different from current_passphrase"}, 400

        if not biometric_confirmed:
            self._flag(username, device_fingerprint, "missing_biometric_confirmation", pi_auth_uid=pi_auth_uid)
            return {"error": "biometric confirmation is required before rotation"}, 403

        current_hash = self._hash(current_passphrase)
        new_hash = self._hash(new_passphrase)
        if new_hash in self.revoked_passphrases:
            self._flag(username, device_fingerprint, "revoked_passphrase_reuse", pi_auth_uid=pi_auth_uid)
            return {"error": "new_passphrase has been revoked and cannot be reused"}, 409

        if mfa_challenge_id:
            challenge = self.mfa_challenges.get(mfa_challenge_id)
            if not challenge or challenge["username"] != username:
                self._flag(username, device_fingerprint, "invalid_mfa_challenge", pi_auth_uid=pi_auth_uid)
                return {"error": "valid MFA challenge is required"}, 403
            challenge_pi_auth_uid = challenge.get("pi_auth_uid")
            if challenge_pi_auth_uid and challenge_pi_auth_uid != pi_auth_uid:
                self._flag(username, device_fingerprint, "pi_auth_mismatch", pi_auth_uid=pi_auth_uid)
                return {"error": "pi_auth_mismatch"}, 403
            challenge["status"] = "verified"
            challenge["verified_at"] = self._now()

        self.revoked_passphrases.add(current_hash)
        record = RotationRecord(
            username=username,
            device_fingerprint=device_fingerprint or "unknown-device",
            rotated_at=self._now(),
            old_passphrase_hash=current_hash,
            new_passphrase_hash=new_hash,
            biometric_confirmed=biometric_confirmed,
            mfa_challenge_id=mfa_challenge_id or "demo-bypass",
            pi_auth_uid=pi_auth_uid,
        )
        self.rotations.append(record)
        return {
            "status": "passphrase_rotated",
            "username": username,
            "rotated_at": record.rotated_at,
            "biometric_confirmed": True,
            "pi_auth_uid": record.pi_auth_uid,
            "device_fingerprint": record.device_fingerprint,
            "revoked_passphrases": len(self.revoked_passphrases),
        }, 200

    def dashboard(self) -> dict[str, Any]:
        return {
            "rotations": len(self.rotations),
            "revoked_passphrases": len(self.revoked_passphrases),
            "suspicious_events": self.suspicious_events[-10:],
            "mfa_challenges": list(self.mfa_challenges.values())[-10:],
        }

    def _flag(
        self,
        username: str,
        device_fingerprint: str,
        reason: str,
        *,
        pi_auth_uid: str | None = None,
    ) -> None:
        self.suspicious_events.append(
            {
                "username": username or "anonymous",
                "device_fingerprint": device_fingerprint or "unknown-device",
                "reason": reason,
                "pi_auth_uid": pi_auth_uid,
                "created_at": self._now(),
            }
        )

    @staticmethod
    def _hash(value: str) -> str:
        return sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
