import pytest

from pishield.backend.security_engine import PiTrustAnalyzer, SecurityEngine
from pishield.backend.security_shared import ConnectionMetadata
from pishield.backend.wallet_manager import build_device_fingerprint


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        (ConnectionMetadata(ip_address="10.0.0.1"), 0),
        (ConnectionMetadata(ip_address="fd00::1"), 0),
        (ConnectionMetadata(ip_address="8.8.8.8"), 0),
        (ConnectionMetadata(ip_address="invalid"), 0),
        (ConnectionMetadata(uses_vpn=True), 20),
        (ConnectionMetadata(uses_tor=True), 35),
        (ConnectionMetadata(uses_vpn=True, uses_tor=True, ip_address="172.16.0.1"), 45),
    ],
)
def test_connection_metadata_drives_bounded_risk_score(metadata, expected):
    score = PiTrustAnalyzer.calculate_risk_score("tor-in-device-id-is-ignored", metadata)
    assert score == expected
    assert 0 <= score <= 100


def test_mfa_challenge_validation_and_pi_auth_uid_binding():
    engine = SecurityEngine()
    challenge = engine.create_mfa_challenge("sandbox-user", "uid-1")
    result, status = engine.rotate_passphrase(
        username="sandbox-user", current_passphrase="old-passphrase", new_passphrase="new-passphrase-123",
        biometric_confirmed=True, device_fingerprint="device", mfa_challenge_id=challenge["challenge_id"], pi_auth_uid="uid-1"
    )
    assert status == 200 and result["status"] == "passphrase_rotated"

    result, status = engine.rotate_passphrase(
        username="sandbox-user", current_passphrase="another-old", new_passphrase="another-new-123",
        biometric_confirmed=True, device_fingerprint="device", mfa_challenge_id="missing", pi_auth_uid="uid-1"
    )
    assert status == 403 and result["error"] == "valid MFA challenge is required"

    challenge = engine.create_mfa_challenge("sandbox-user", "uid-2")
    result, status = engine.rotate_passphrase(
        username="sandbox-user", current_passphrase="third-old", new_passphrase="third-new-passphrase",
        biometric_confirmed=True, device_fingerprint="device", mfa_challenge_id=challenge["challenge_id"], pi_auth_uid="wrong"
    )
    assert status == 403 and result["error"] == "pi_auth_mismatch"


def test_device_fingerprint_is_deterministic_and_does_not_expose_user_agent():
    fingerprint = build_device_fingerprint("Mozilla/Test", "sandbox-user")
    assert fingerprint == build_device_fingerprint("Mozilla/Test", "sandbox-user")
    assert "Mozilla/Test" not in fingerprint


def test_config_aliases_are_driven_by_pios_config():
    from pishield.backend import config

    assert config.PI_SANDBOX is True
    assert config.PI_APP_NAME == config.PiOSConfig.APP_NAME
    assert config.PI_APP_URL == config.PiOSConfig.DEV_APP_URL
    assert config.PI_API_URL == config.PiOSConfig.API_URL
    assert config.PI_SANDBOX_URL == config.PiOSConfig.SANDBOX_URL
