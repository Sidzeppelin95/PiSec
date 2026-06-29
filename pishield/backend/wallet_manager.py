diff --git a/pishield/backend/wallet_manager.py b/pishield/backend/wallet_manager.py
index 8b137891791fe96927ad78e64b0aad7bded08bdc..5fef873933cbac9379bc05389424e0b9e3878013 100644
--- a/pishield/backend/wallet_manager.py
+++ b/pishield/backend/wallet_manager.py
@@ -1 +1,11 @@
+"""Wallet helpers for the PiShield sandbox demo."""
 
+from __future__ import annotations
+
+from hashlib import sha256
+
+
+def build_device_fingerprint(user_agent: str, pi_username: str) -> str:
+    """Return a stable demo fingerprint without storing raw browser details."""
+    raw = f"{user_agent}|{pi_username}".encode("utf-8")
+    return sha256(raw).hexdigest()[:24]
