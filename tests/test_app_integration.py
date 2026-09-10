from datetime import timezone

import pytest

from pishield.backend import app as app_module
from pishield.backend.security_engine import PiSecurityEngine
from pishield.backend.security_shared import SecurityUtils, utc_now
from pishield.backend.wallet_manager import PiWalletManager


@pytest.fixture(autouse=True)
def reset_application_state():
    app_module.wallet_manager.wallets.clear()
    app_module.security_engine.rotations.clear()
    app_module.security_engine.revoked_passphrases.clear()
    app_module.security_engine.suspicious_events.clear()
    app_module.security_engine.mfa_challenges.clear()
    yield


@pytest.fixture
def client():
    return app_module.app.test_client()


def test_flask_endpoints_preserve_sandbox_behavior(client):
    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/pi/validate").status_code == 200
    assert client.get("/api/config").status_code == 200
    assert client.post("/api/mfa/challenge", json={"username": "sandbox-user"}).status_code == 200
    assert client.post("/api/wallet/fingerprint", json={"username": "sandbox-user"}).status_code == 200
    assert client.post("/api/wallet/rotate-passphrase", json={}).status_code == 400
    assert client.get("/api/security/dashboard").status_code == 200


@pytest.mark.parametrize("pi_auth_uid", ["", 42])
def test_rotate_rejects_empty_or_invalid_pi_auth_uid(client, pi_auth_uid):
    response = client.post("/api/wallet/rotate-passphrase", json={"pi_auth_uid": pi_auth_uid})
    assert response.status_code == 400


def test_rotate_accepts_valid_pi_auth_uid(client):
    response = client.post(
        "/api/wallet/rotate-passphrase",
        json={
            "username": "sandbox-user",
            "current_passphrase": "old-demo-passphrase",
            "new_passphrase": "new-demo-passphrase",
            "biometric_confirmed": True,
            "pi_auth_uid": "uid-123",
        },
    )
    assert response.status_code == 200
    assert response.get_json()["pi_auth_uid"] == "uid-123"


def test_application_wires_revoked_credential_to_recovery_lock(client):
    assert isinstance(app_module.pi_security_engine, PiSecurityEngine)
    assert isinstance(app_module.wallet_manager, PiWalletManager)
    assert app_module.wallet_manager.response_handler is app_module.pi_security_engine

    wallet = app_module.wallet_manager.create_wallet("sandbox-user", "active-demo")
    wallet.revoked_passphrase_hashes.add(SecurityUtils.hash_passphrase("revoked-demo"))
    response = client.post(
        "/api/wallet/authenticate",
        json={"username": "sandbox-user", "demo_credential": "revoked-demo"},
    )

    assert response.status_code == 403
    assert response.get_json()["authenticated"] is False
    assert wallet.recovery_locked_until > utc_now()
    assert wallet.recovery_locked_until.tzinfo is timezone.utc
    assert app_module.security_engine.suspicious_events[-1]["reason"] == "revoked_demo_credential_attempt"


def test_authentication_endpoint_blocks_active_credential_while_locked(client):
    wallet = app_module.wallet_manager.create_wallet("sandbox-user", "active-demo")
    wallet.recovery_locked_until = utc_now().replace(year=utc_now().year + 1)
    response = client.post(
        "/api/wallet/authenticate",
        json={"username": "sandbox-user", "demo_credential": "active-demo"},
    )
    assert response.status_code == 403

@pytest.mark.parametrize("pi_auth_uid", ["", 42])
def test_mfa_challenge_rejects_empty_or_invalid_pi_auth_uid(client, pi_auth_uid):
    response = client.post("/api/mfa/challenge", json={"pi_auth_uid": pi_auth_uid})
    assert response.status_code == 400


def test_mfa_challenge_accepts_valid_pi_auth_uid(client):
    response = client.post("/api/mfa/challenge", json={"pi_auth_uid": "uid-123"})
    assert response.status_code == 200
    assert response.get_json()["pi_auth_uid"] == "uid-123"
