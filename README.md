# PiShield

## Secure Passphrase Rotation and Wallet Protection for the Pi Ecosystem

PiShield is a security-focused prototype that introduces a secure passphrase rotation mechanism for Pi Wallets while preserving the same wallet identity. The project aims to reduce phishing-related wallet compromises by allowing users to replace compromised passphrases without migrating to a new wallet.

The prototype is designed for integration with the Pi Browser, Pi SDK, and Pi Sandbox environment during development.

---

## Project Objectives

* Enable secure passphrase rotation without changing the wallet.
* Protect users against phishing attacks involving leaked passphrases.
* Detect attempts to access wallets using revoked passphrases.
* Distinguish between legitimate recovery attempts and suspicious access attempts.
* Support biometric and multi-factor verification during secure recovery.
* Maintain complete audit logs for security analysis.
* Operate within the Pi Sandbox for testing and future PiOS compatibility.

---

## Features

* Secure passphrase rotation
* Revoked passphrase database
* Behavioral trust analysis
* Trusted device recognition
* Trusted IP recognition
* Suspicious recovery detection
* Biometric verification workflow
* Multi-factor authentication support
* Security event logging
* Manual security review workflow
* Pi Browser compatibility
* Pi SDK v2.0 support
* Sandbox mode support

---

## Project Structure

```text
pishield/
│
├── backend/
│   ├── app.py
│   ├── config.py
│   ├── security_engine.py
│   ├── security_shared.py
│   └── wallet_manager.py
│
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── styles.css
│
├── tests/
├── requirements.txt
└── README.md
```

---

## Technology Stack

### Backend

* Python 3.11+
* Flask
* Flask-CORS

### Frontend

* HTML5
* JavaScript
* CSS3
* Pi SDK v2.0

### Development Tools

* Pi Browser
* Pi Sandbox
* ngrok
* GitHub

---

## Installation

Clone the repository.

```bash
git clone https://github.com/<username>/PiShield.git

cd PiShield
```

Install dependencies.

```bash
pip install -r requirements.txt
```

---

## Running the Backend

Navigate to the backend directory.

```bash
cd backend
```

Start the Flask server.

```bash
python app.py
```

Expected output:

```text
Running on http://localhost:31415
```

---

## Starting ngrok

Expose the local server.

```bash
ngrok http 31415
```

Example output:

```text
https://your-app.ngrok-free.dev
```

Use this URL as the Development URL in the Pi Developer Portal.

---

## Pi Sandbox Configuration

Include the Pi SDK.

```html
<script src="https://sdk.minepi.com/pi-sdk.js"></script>
```

Initialize the SDK.

```javascript
Pi.init({
    version: "2.0",
    sandbox: true
});
```

---

## Pi Developer Portal Configuration

Development URL

```
https://your-app.ngrok-free.dev
```

Privacy Policy URL

```
https://your-domain/privacy-policy
```

Terms of Service URL

```
https://your-domain/terms
```

---

## Security Workflow

1. User authenticates using the active wallet passphrase.
2. User requests passphrase rotation.
3. Identity verification is performed.
4. Existing passphrase is revoked.
5. New passphrase becomes active.
6. Wallet identity remains unchanged.
7. Any attempt using a revoked passphrase is denied.
8. Recovery attempts are analyzed for legitimacy.
9. Suspicious activity is flagged for review.
10. Security responses are applied according to the calculated risk.

---

## Threat Detection

PiShield evaluates multiple trust signals, including:

* Trusted device history
* Trusted IP addresses
* Device fingerprint
* Biometric availability
* VPN detection
* Tor detection
* Previous recovery history
* Suspicious behavioral patterns

Each event receives a calculated risk score and classification.

---

## Recovery Classification

Possible classifications include:

* Likely Genuine Owner Recovery
* Verification Required
* Likely Phishing Actor

Revoked passphrases never grant wallet access, regardless of the classification.

---

## Security Components

* Passphrase Rotation Engine
* Trust Analyzer
* Security Engine
* Recovery Verification
* Device Recognition
* Audit Logger
* Manual Review System

---

## Sandbox Testing

The application is intended to run within the Pi Sandbox environment before deployment.

Testing includes:

* Pi SDK authentication
* Sandbox login
* Wallet simulation
* Recovery simulation
* Revoked passphrase validation
* Security event generation

---

## Future Enhancements

* Device fingerprint database
* Behavioral machine learning
* Geolocation anomaly detection
* Hardware-backed biometric verification
* Risk prediction engine
* Administrative security dashboard
* Notification service
* Encrypted audit storage

---

## Disclaimer

This repository is a research and development prototype intended to demonstrate secure wallet recovery concepts and passphrase rotation workflows. It is not affiliated with or endorsed by the Pi Core Team and should not be used in production without comprehensive security review, testing, and integration with the official Pi platform.

---

## Sandbox security architecture

PiShield is a **sandbox demonstration**. It does not connect to Pi Wallets, change
real Pi Wallet credentials, transmit credentials to third parties, or represent a
production credential provider. The demo-only credential hashes stay in process
memory and are never returned by the API.

The Flask application keeps general MFA, rotation, audit, and dashboard behavior
in `SecurityEngine`. Its sandbox authentication path is intentionally separate:
`PiWalletManager` decides whether a demo credential is active, revoked, or
invalid. It receives `PiSecurityEngine` through the narrow
`RecoveryResponseHandler` interface. A revoked demo credential is denied and
causes a temporary recovery lock; it records a security signal, not a conclusion
that a person is a scammer or that phishing is confirmed.

Wallet timestamps are normalized to timezone-aware UTC at the `Wallet` boundary.
While a recovery lock is active, all authentication attempts—including active,
revoked, and invalid demo credentials—are denied. Expired locks do not prevent a
valid active demo credential from being accepted.

`PiTrustAnalyzer` is advisory only. It accepts explicit connection metadata
(`uses_vpn`, `uses_tor`, and `ip_address`) rather than inferring network behavior
from a device ID. VPN/Tor use, IP addresses, and fingerprints do not independently
identify a user as malicious. Confirmed phishing activity is assigned only by the
separate analyst review workflow.

### Validation

Run the sandbox regression suite from the repository root:

```bash
python -m compileall -q pishield
pytest -q
python -m pytest -q
git diff --check
```
