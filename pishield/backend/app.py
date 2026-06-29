from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

if __package__:
    from .config import PI_APP_NAME, PI_APP_URL, PI_NETWORK, PI_SANDBOX, PI_SANDBOX_URL
    from .security_engine import SecurityEngine
    from .wallet_manager import build_device_fingerprint
else:
    from config import PI_APP_NAME, PI_APP_URL, PI_NETWORK, PI_SANDBOX, PI_SANDBOX_URL
    from security_engine import SecurityEngine
    from wallet_manager import build_device_fingerprint
 
app = Flask(__name__)
 CORS(app)
 
security_engine = SecurityEngine()
FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


 @app.route("/")
 def home():

     return jsonify({
        "app": PI_APP_NAME,
        "status": "sandbox_running",
        "pi_network": "sandbox" if PI_SANDBOX else PI_NETWORK,
        "security": "enabled",
        "app_url": PI_APP_URL,
        "sandbox_url": PI_SANDBOX_URL,
    })
 
@app.route("/app")
def frontend_app():
    return send_from_directory(FRONTEND_DIR, "index.html")
@app.route("/frontend/<path:filename>")
def frontend_asset(filename):
    return send_from_directory(FRONTEND_DIR, filename)
 
 
 @app.route("/health")
 def health():
    return jsonify({
        "server": "online",
        "wallet_security": "active",
        "sandbox": PI_SANDBOX,
    })

 
@app.route("/pi/validate")
def validate():
     return jsonify({
        "app": PI_APP_NAME,
        "verified": True,
        "network": "sandbox" if PI_SANDBOX else PI_NETWORK,
    })
 
@app.route("/api/config")
def frontend_config():
    return jsonify({
        "app": PI_APP_NAME,
        "network": PI_NETWORK,
        "sandbox": PI_SANDBOX,
        "app_url": PI_APP_URL,
        "sandbox_url": PI_SANDBOX_URL,
     })
 

@app.route("/api/mfa/challenge", methods=["POST"])
def create_mfa_challenge():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "pi_sandbox_user")
    pi_auth_uid = payload.get("pi_auth_uid")
    return jsonify(security_engine.create_mfa_challenge(username, pi_auth_uid=pi_auth_uid))


@app.route("/api/wallet/fingerprint", methods=["POST"])
def fingerprint():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "pi_sandbox_user")
    user_agent = request.headers.get("User-Agent", "unknown-agent")
    return jsonify({
        "username": username,
        "device_fingerprint": build_device_fingerprint(user_agent, username),
    })

@app.route("/api/wallet/rotate-passphrase", methods=["POST"])
def rotate_passphrase():
    payload = request.get_json(silent=True) or {}
    pi_auth_uid = payload.get("pi_auth_uid")
    if "pi_auth_uid" in payload and (not isinstance(pi_auth_uid, str) or not pi_auth_uid.strip()):
        return jsonify({
            "error": "invalid_pi_auth_uid",
            "message": "If provided, pi_auth_uid must be a non-empty string.",
        }), 400

    result, status = security_engine.rotate_passphrase(
        username=payload.get("username", "pi_sandbox_user"),
        current_passphrase=payload.get("current_passphrase", ""),
        new_passphrase=payload.get("new_passphrase", ""),
        biometric_confirmed=bool(payload.get("biometric_confirmed")),
        device_fingerprint=payload.get("device_fingerprint", ""),
        mfa_challenge_id=payload.get("mfa_challenge_id"),
        pi_auth_uid=pi_auth_uid.strip() if isinstance(pi_auth_uid, str) else None,
     )
    return jsonify(result), status


@app.route("/api/security/dashboard")
def security_dashboard():
    return jsonify(security_engine.dashboard())


if __name__ == "__main__":
+    app.run(host="0.0.0.0", port=31415, debug=True)
