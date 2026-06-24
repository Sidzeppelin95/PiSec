"""PiShield trust analysis and revoked-passphrase response engine.

Old passphrases never provide wallet access. Revoked passphrase attempts are
used only to analyze intent, evaluate trust signals, assist secure recovery,
flag suspicious behavior, and escalate questionable attempts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Dict, Optional

from config import PiOSConfig
from wallet_manager import SecurityUtils

if TYPE_CHECKING:
    from wallet_manager import PiWallet


@dataclass
class SecurityEvent:
    """Audit record for wallet recovery and suspicious authentication events."""

    event_id: str
    wallet_id: str
    timestamp: datetime
    ip_address: str
    device_id: str
    risk_score: int
    classification: str
    status: str
    recovery_attempt: bool
    analyst_notes: Optional[str] = None


security_events_db: Dict[str, SecurityEvent] = {}


class PiTrustAnalyzer:
    """Evaluates device and network signals for revoked-passphrase attempts."""

    @staticmethod
    def is_trusted_device(wallet: "PiWallet", device_id: str) -> bool:
        return any(device.device_id == device_id for device in wallet.trusted_devices)

    @staticmethod
    def is_trusted_ip(wallet: "PiWallet", ip_address: str) -> bool:
        return ip_address in wallet.trusted_ips

    @staticmethod
    def get_device(wallet: "PiWallet", device_id: str):
        for device in wallet.trusted_devices:
            if device.device_id == device_id:
                return device
        return None

    @staticmethod
    def calculate_risk_score(wallet: "PiWallet", ip_address: str, device_id: str) -> int:
        score = 0
        trusted_device = PiTrustAnalyzer.is_trusted_device(wallet, device_id)
        trusted_ip = PiTrustAnalyzer.is_trusted_ip(wallet, ip_address)

        if not trusted_device:
            score += 40

        if not trusted_ip:
            score += 30

        device = PiTrustAnalyzer.get_device(wallet, device_id)
        if device:
            if not device.pi_browser_verified:
                score += 20
            if not device.biometric_enabled:
                score += 15

        lowered_device_id = device_id.lower()
        if "vpn" in lowered_device_id:
            score += 20
        if "tor" in lowered_device_id:
            score += 35

        if ip_address.startswith("192.168"):
            score -= 10

        return max(0, min(score, 100))

    @staticmethod
    def classify_attempt(risk_score: int, trusted_device: bool, trusted_ip: bool) -> str:
        if trusted_device and trusted_ip and risk_score < 40:
            return "LIKELY_GENUINE_OWNER_RECOVERY"

        if risk_score < PiOSConfig.THREAT_SCORE_THRESHOLD:
            return "VERIFICATION_REQUIRED"

        return "LIKELY_PHISHING_ACTOR"


class PiSecurityEngine:
    """Creates security events and triggers recovery or escalation responses."""

    @staticmethod
    def handle_old_passphrase_attempt(wallet: "PiWallet", ip_address: str, device_id: str) -> SecurityEvent:
        trusted_device = PiTrustAnalyzer.is_trusted_device(wallet, device_id)
        trusted_ip = PiTrustAnalyzer.is_trusted_ip(wallet, ip_address)
        risk_score = PiTrustAnalyzer.calculate_risk_score(wallet, ip_address, device_id)
        classification = PiTrustAnalyzer.classify_attempt(
            risk_score,
            trusted_device,
            trusted_ip,
        )

        event = SecurityEvent(
            event_id=SecurityUtils.generate_id(),
            wallet_id=wallet.wallet_id,
            timestamp=SecurityUtils.utc_now(),
            ip_address=ip_address,
            device_id=device_id,
            risk_score=risk_score,
            classification=classification,
            status="FLAGGED",
            recovery_attempt=True,
        )
        security_events_db[event.event_id] = event

        PiSecurityEngine.trigger_response(wallet, event)
        return event

    @staticmethod
    def trigger_response(wallet: "PiWallet", event: SecurityEvent) -> None:
        if event.classification == "LIKELY_GENUINE_OWNER_RECOVERY":
            event.status = "RECOVERY_VERIFICATION_REQUIRED"
            return

        if event.classification == "VERIFICATION_REQUIRED":
            event.status = "SECURITY_REVIEW_QUEUED"
            return

        if event.classification == "LIKELY_PHISHING_ACTOR":
            wallet.suspicious_attempt_count += 1
            wallet.recovery_locked_until = SecurityUtils.utc_now() + timedelta(
                hours=PiOSConfig.RECOVERY_LOCK_HOURS,
            )
            event.status = "ESCALATED"


class PiSecurityReviewSystem:
    """Analyst review workflow for flagged security events."""

    @staticmethod
    def review_event(event_id: str, suspicious: bool, notes: str) -> SecurityEvent:
        event = security_events_db.get(event_id)
        if not event:
            raise ValueError("Security event not found")

        event.analyst_notes = notes
        if suspicious:
            event.status = "CONFIRMED_PHISHING_ACTIVITY"
            PiSecurityReviewSystem.take_action(event)
        else:
            event.status = "FALSE_POSITIVE"

        return event

    @staticmethod
    def take_action(event: SecurityEvent) -> None:
        # Placeholder for integrations with monitoring, device blacklists, and
        # Pi ecosystem alerting systems.
        event.status = "CONFIRMED_PHISHING_ACTIVITY"
