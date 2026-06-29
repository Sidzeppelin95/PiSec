diff --git a/pishield/backend/config.py b/pishield/backend/config.py
index 63332c68ddcc50a20c30d8ff0aa03a0110879648..32e37713b3db50842b203293e80a2c478f173d0d 100644
--- a/pishield/backend/config.py
+++ b/pishield/backend/config.py
@@ -1,19 +1,34 @@
-PI_SANDBOX = True
+"""PiShield sandbox configuration.
 
-PI_APP_NAME = "PiShield"
+Values default to the Pi Developer Portal sandbox settings and can be
+overridden with environment variables for local/ngrok development.
+"""
 
-PI_API_KEY = "YOUR_PI_API_KEY"
+import os
+from dotenv import load_dotenv
 
-PI_NETWORK = "Pi Testnet"
+load_dotenv()
 
-PI_APP_URL = "http://localhost:31415"
 
-PI_SANDBOX_URL = "https://sandbox.minepi.com"
+def _env_bool(name: str, default: bool) -> bool:
+    value = os.getenv(name)
+    if value is None:
+        return default
+    return value.strip().lower() in {"1", "true", "yes", "on"}
 
-PRIVACY_POLICY_URL = (
-    "https://pishield.pinet.com/privacy-policy"
-)
 
-TERMS_OF_SERVICE_URL = (
-    "https://pishield.pinet.com/terms"
+PI_SANDBOX = _env_bool("PI_SANDBOX", True)
+PI_APP_NAME = os.getenv("PI_APP_NAME", "PiShield")
+PI_API_KEY = os.getenv("PI_API_KEY", "YOUR_PI_API_KEY")
+PI_NETWORK = os.getenv("PI_NETWORK", "Pi Testnet")
+PI_APP_URL = os.getenv("PI_APP_URL", "http://localhost:31415")
+PI_API_URL = os.getenv("PI_API_URL", "https://api.minepi.com")
+PI_SANDBOX_URL = os.getenv("PI_SANDBOX_URL", "https://sandbox.minepi.com")
+PRIVACY_POLICY_URL = os.getenv(
+    "PRIVACY_POLICY_URL",
+    "https://pishield.pinet.com/privacy-policy",
+)
+TERMS_OF_SERVICE_URL = os.getenv(
+    "TERMS_OF_SERVICE_URL",
+    "https://pishield.pinet.com/terms",
 )
