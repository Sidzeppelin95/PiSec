from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)

CORS(app)

@app.route("/")
def home():

    return jsonify({

        "app": "PiShield",

        "status": "sandbox_running",

        "pi_network": "sandbox",

        "security": "enabled"
    })


@app.route("/health")
def health():

    return jsonify({

        "server": "online",

        "wallet_security": "active"
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=31415,
        debug=True
    )
