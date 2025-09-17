import os
import hmac
import hashlib
import json
import requests
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# Max request size (default 1MB)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 1024 * 1024))

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("finora")

# HMAC verification secret for webhooks
HMAC_SECRET = os.environ.get("WEBHOOK_HMAC_SECRET", "").strip()

# BitGo configuration - UPDATED TO USE YOUR EXPRESS SERVICE
BITGO_ACCESS_TOKEN = os.environ.get("BITGO_ACCESS_TOKEN")
BITGO_WALLET_ID = os.environ.get("BITGO_WALLET_ID")
BITGO_WALLET_PASSPHRASE = os.environ.get("BITGO_WALLET_PASSPHRASE")
BITGO_EXPRESS_URL = "https://finora-bitgo-express-1.onrender.com"  # ← YOUR EXPRESS SERVICE

def verify_hmac_sha256(raw_body: bytes, received_sig: str) -> bool:
    """Verify webhook HMAC signature"""
    if not HMAC_SECRET:
        return True  # Skip verification if secret not set
    if not received_sig:
        return False
    if "=" in received_sig:
        _, received_sig = received_sig.split("=", 1)
    computed = hmac.new(HMAC_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed.lower(), received_sig.strip().lower())

# Health endpoints
@app.route("/")
def home():
    return "Finora backend is running 🚀"

@app.route("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}, 200

# Send TBTC endpoint - UPDATED TO USE BITGO EXPRESS
@app.route("/api/send-tbtc", methods=["POST"])
def send_tbtc():
    try:
        data = request.json
        logger.info(f"Send request received: {data}")

        address = data.get("address")
        amount = data.get("amount")  # Expected in satoshis

        if not address or not amount:
            return jsonify({"error": "Address and amount are required"}), 400

        # UPDATED: Use your BitGo Express service
        bitgo_url = f"{BITGO_EXPRESS_URL}/api/v2/tbtc/wallet/{BITGO_WALLET_ID}/sendcoins"

        payload = {
            "address": address,
            "amount": int(amount),  # Must be integer in satoshis
            "walletPassphrase": BITGO_WALLET_PASSPHRASE
        }

        headers = {
            "Authorization": f"Bearer {BITGO_ACCESS_TOKEN}",
            "Content-Type": "application/json"
        }

        response = requests.post(bitgo_url, json=payload, headers=headers, timeout=30)

        if response.status_code == 200:
            logger.info(f"Transaction successful: {response.json()}")
            return jsonify(response.json()), 200
        else:
            logger.error(f"BitGo Express error: {response.status_code} - {response.text}")
            return jsonify({"error": "Transaction failed", "details": response.text}), response.status_code

    except Exception as e:
        logger.error(f"Send transaction error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# BitGo webhook endpoint - UNCHANGED (KEEP THIS AS IS)
@app.route("/webhook/bitgo", methods=["POST"])
def bitgo_webhook():
    ctype = request.headers.get("Content-Type", "")
    if "application/json" not in ctype.lower():
        return jsonify({"error": "Unsupported media type"}), 415

    raw_body = request.get_data(cache=False, as_text=False)
    sig = request.headers.get("X-Signature-SHA256") or request.headers.get("X-Hub-Signature-256", "")

    if not verify_hmac_sha256(raw_body, sig):
        logger.warning("Webhook signature verification failed")
        return jsonify({"error": "Invalid signature"}), 401

    try:
        data = json.loads(raw_body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 400

    wtype = data.get("type")
    state = data.get("state")
    logger.info(f"Webhook received: {wtype} - {state}")

    if wtype == "transfer" and state == "confirmed":
        value = data.get("value", {})
        logger.info(f"💰 Deposit: {value.get('amount')} {value.get('currency')} TX: {data.get('hash')}")

    return jsonify({"status": "OK"}), 200

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "10000"))
    app.run(host=host, port=port, debug=False)
