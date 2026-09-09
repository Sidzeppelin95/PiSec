"""PiShield sandbox configuration."""
from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class PiOSConfig:
    """Configuration values for Pi Browser and wallet-security workflows."""

    APP_NAME = os.getenv("PI_APP_NAME", "PiShield")
    APP_VERSION = "1.0.0"
    PIOS_COMPATIBLE = True

    PROD_APP_URL = os.getenv("PI_PROD_APP_URL", "https://pishield.pinet.com")
    DEV_APP_URL = os.getenv("PI_APP_URL", "http://localhost:31415")
    API_URL = os.getenv("PI_API_URL", "https://api.minepi.com")
    PRIVACY_POLICY_URL = os.getenv(
        "PRIVACY_POLICY_URL", "https://pishield.pinet.com/privacy-policy"
    )
    TERMS_OF_SERVICE_URL = os.getenv(
        "TERMS_OF_SERVICE_URL", "https://pishield.pinet.com/terms"
    )
    SANDBOX_URL = os.getenv("PI_SANDBOX_URL", "https://sandbox.minepi.com")

    PI_BROWSER_REQUIRED = True
    PI_SDK_ENABLED = True
    PI_MAINNET_ENABLED = True

    ROTATION_DELAY_HOURS = 48
    RECOVERY_LOCK_HOURS = 24
    THREAT_SCORE_THRESHOLD = 70
    HIGH_RISK_THRESHOLD = 90
    MAX_RECOVERY_ATTEMPTS = 3


# Backwards-compatible aliases used by the existing Flask app/config imports.
# TODO: migrate callers to PiOSConfig and remove these aliases.
PI_SANDBOX = _env_bool("PI_SANDBOX", True)
PI_APP_NAME = PiOSConfig.APP_NAME
PI_API_KEY = os.getenv("PI_API_KEY", "YOUR_PI_API_KEY")
PI_NETWORK = os.getenv("PI_NETWORK", "Pi Testnet")
# Legacy Flask uses the development URL for the app.
PI_APP_URL = PiOSConfig.DEV_APP_URL
PI_API_URL = PiOSConfig.API_URL
PI_SANDBOX_URL = PiOSConfig.SANDBOX_URL
PRIVACY_POLICY_URL = PiOSConfig.PRIVACY_POLICY_URL
TERMS_OF_SERVICE_URL = PiOSConfig.TERMS_OF_SERVICE_URL
