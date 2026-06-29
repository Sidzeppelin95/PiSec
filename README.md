diff --git a/README.md b/README.md
index fea98fcddc22929f57d795b69d33395813e63611..13fedbaa54f25629d3f9d532e8e4dd090298bb4f 100644
--- a/README.md
+++ b/README.md
@@ -1,2 +1,53 @@
-# PiSec
-Rotating wallet pp
+# PiShield
+
+PiShield is a Pi Network sandbox demonstration app for crypto wallet passphrase protection. It shows a secure passphrase rotation flow gated by Pi SDK authentication, device fingerprinting, MFA challenge creation, and biometric confirmation.
+
+## Project structure
+
+```text
+pishield/
+  backend/
+    app.py
+    config.py
+    security_engine.py
+    wallet_manager.py
+  frontend/
+    index.html
+    app.js
+    styles.css
+requirements.txt
+```
+
+## Local setup
+
+```bash
+pip install -r requirements.txt
+python pishield/backend/app.py
+```
+
+The Flask sandbox server runs on `http://localhost:31415`; open the demo UI at `http://localhost:31415/app`.
+
+## Pi Developer Portal sandbox configuration
+
+Use `http://localhost:31415` as the local Development URL. If Pi Browser needs an externally accessible URL, expose the same port with ngrok:
+
+```bash
+ngrok http 31415
+```
+
+Use the generated `https://*.ngrok-free.app` URL as the Development URL and Sandbox URL in the Pi Developer Portal.
+
+## Verification endpoints
+
+- `GET /` returns sandbox app metadata.
+- `GET /app` serves the PiShield sandbox UI.
+- `GET /health` returns server and wallet-security health.
+- `GET /pi/validate` returns Pi sandbox validation metadata.
+- `POST /api/mfa/challenge` creates a biometric MFA challenge and can bind it to an optional `pi_auth_uid`.
+- `POST /api/wallet/fingerprint` returns a demo device fingerprint.
+- `POST /api/wallet/rotate-passphrase` rotates and revokes the previous passphrase after biometric confirmation, rejects invalid `pi_auth_uid` values, and checks the UID against any UID-bound MFA challenge.
+- `GET /api/security/dashboard` returns demo security telemetry.
+
+## Security notes
+
+Always use HTTPS outside local development, open the app in Pi Browser, validate Pi auth tokens server-side, keep sandbox and production databases separate, and disable mainnet payments while sandbox mode is enabled.
