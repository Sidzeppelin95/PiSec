from datetime import datetime, timedelta, timezone

import pytest

from pishield.backend.config import PiOSConfig
from pishield.backend.security_engine import PiSecurityEngine
from pishield.backend.security_shared import SecurityUtils, Wallet, utc_now
from pishield.backend.wallet_manager import PiWalletManager


class RecordingHandler:
    def __init__(self):
        self.wallets = []

    def trigger_response(self, wallet):
        self.wallets.append(wallet)


def make_wallet(**kwargs):
    return Wallet(
        username="sandbox-user",
        active_passphrase_hash=SecurityUtils.hash_passphrase("active-demo"),
        **kwargs,
    )


def test_wallet_timestamps_are_aware_utc_and_normalize_naive_values():
    naive = datetime(2026, 1, 1, 12, 0)
    wallet = make_wallet(created_at=naive, recovery_locked_until=naive)
    assert wallet.created_at.tzinfo is timezone.utc
    assert wallet.recovery_locked_until.tzinfo is timezone.utc


def test_aware_non_utc_lock_is_converted_to_utc():
    eastern = timezone(timedelta(hours=-4))
    lock = datetime(2026, 1, 1, 12, 0, tzinfo=eastern)
    wallet = make_wallet(recovery_locked_until=lock)
    assert wallet.recovery_locked_until == datetime(2026, 1, 1, 16, 0, tzinfo=timezone.utc)


def test_naive_lock_does_not_raise_and_blocks_authentication():
    manager = PiWalletManager()
    wallet = make_wallet(recovery_locked_until=datetime.now() + timedelta(hours=1))
    manager.wallets[wallet.username] = wallet
    assert manager.authenticate(wallet.username, "active-demo") is False


def test_expired_lock_allows_active_credential():
    manager = PiWalletManager()
    wallet = make_wallet(recovery_locked_until=utc_now() - timedelta(seconds=1))
    manager.wallets[wallet.username] = wallet
    assert manager.authenticate(wallet.username, "active-demo") is True


@pytest.mark.parametrize("credential", ["active-demo", "revoked-demo", "invalid-demo"])
def test_future_lock_blocks_every_credential_type(credential):
    manager = PiWalletManager()
    wallet = make_wallet(recovery_locked_until=utc_now() + timedelta(hours=1))
    wallet.revoked_passphrase_hashes.add(SecurityUtils.hash_passphrase("revoked-demo"))
    manager.wallets[wallet.username] = wallet
    assert manager.authenticate(wallet.username, credential) is False


def test_active_and_revoked_credential_behavior_with_handler():
    handler = RecordingHandler()
    manager = PiWalletManager(response_handler=handler)
    wallet = manager.create_wallet("sandbox-user", "active-demo")
    wallet.revoked_passphrase_hashes.add(SecurityUtils.hash_passphrase("revoked-demo"))
    assert manager.authenticate(wallet.username, "active-demo") is True
    assert manager.authenticate(wallet.username, "revoked-demo") is False
    assert handler.wallets == [wallet]


def test_revoked_credential_without_handler_fails_safely():
    manager = PiWalletManager()
    wallet = manager.create_wallet("sandbox-user", "active-demo")
    wallet.revoked_passphrase_hashes.add(SecurityUtils.hash_passphrase("revoked-demo"))
    assert manager.authenticate(wallet.username, "revoked-demo") is False


def test_pi_security_engine_applies_aware_configured_lock():
    wallet = make_wallet()
    before = utc_now()
    PiSecurityEngine().trigger_response(wallet)
    assert wallet.recovery_locked_until.tzinfo is timezone.utc
    expected = before + timedelta(hours=PiOSConfig.RECOVERY_LOCK_HOURS)
    assert abs((wallet.recovery_locked_until - expected).total_seconds()) < 1


def test_injected_pi_security_engine_locks_wallet_after_revoked_credential():
    engine = PiSecurityEngine()
    manager = PiWalletManager(response_handler=engine)
    wallet = manager.create_wallet("sandbox-user", "active-demo")
    wallet.revoked_passphrase_hashes.add(SecurityUtils.hash_passphrase("revoked-demo"))
    assert manager.authenticate(wallet.username, "revoked-demo") is False
    assert wallet.recovery_locked_until > utc_now()
