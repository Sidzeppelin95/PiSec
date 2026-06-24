"""PiShield PiOS-compatible configuration."""


class PiOSConfig:
    """Configuration values for Pi Browser and wallet-security workflows."""

    APP_NAME = "PiShield"
    APP_VERSION = "1.0.0"
    PIOS_COMPATIBLE = True

    APP_URL = "https://pishield.pinet.com"
    DEV_URL = "http://localhost:31415"
    API_URL = "https://api.pishield.pinet.com"
    PRIVACY_POLICY_URL = "https://pishield.pinet.com/privacy-policy"
    TERMS_OF_SERVICE_URL = "https://pishield.pinet.com/terms"

    PI_BROWSER_REQUIRED = True
    PI_SDK_ENABLED = True
    PI_MAINNET_ENABLED = True

    ROTATION_DELAY_HOURS = 48
    RECOVERY_LOCK_HOURS = 24
    THREAT_SCORE_THRESHOLD = 70
    HIGH_RISK_THRESHOLD = 90
    MAX_RECOVERY_ATTEMPTS = 3


# Backwards-compatible aliases used by the existing Flask app/config imports.
PI_SANDBOX = True
PI_APP_NAME = PiOSConfig.APP_NAME
PI_API_KEY = "YOUR_PI_API_KEY"
PI_NETWORK = "Pi Testnet"
PI_APP_URL = PiOSConfig.DEV_URL
PI_SANDBOX_URL = "https://sandbox.minepi.com"
PRIVACY_POLICY_URL = PiOSConfig.PRIVACY_POLICY_URL
TERMS_OF_SERVICE_URL = PiOSConfig.TERMS_OF_SERVICE_URL
