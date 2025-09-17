import os
import hmac
import hashlib
import json
import requests  # Add this import
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 1024 * 1024))
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("finora")

# HMAC verification - will be disabled if secret is empty
HMAC_SECRET = os.environ.get("WEBHOOK_HMAC_SECRET", "").strip()

# BitGo configuration
BITGO_ACCESS_TOKEN = os.environ.get("BITGO_ACCESS_TOKEN")
BITGO_WALLET_ID = os.environ.get("BITGO_WALLET_ID")
BITGO_WALLET_PASSPHRASE = os.environ.get("BITGO_WALLET_PASSPHRASE")
BITGO_BASE_URL = "https://app.bitgo-test.com"  # For testnet

def verify_hmac_sha256(raw_body: bytes, received_sig: str) -> bool:
    """HMAC verification - returns True if no secret is set"""
    if not HMAC_SECRET:
        return True
    if not received_sig:
        return False
    if "=" in received_sig:
        _, received_sig = received_sig.split("=", 1)
    computed = hmac.new(HMAC_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed.lower(), received_sig.strip().lower())

@app.route("/")
def home():
    return "Finora backend is running 🚀"

@app.route("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}, 200

# NEW ENDPOINT: Send coins
@app.route("/api/send-tbtc", methods=["POST"])
def send_tbtc():
    try:
        data = request.json
        logger.info(f"Send request received: {data}")
        
        # Validate required fields
        address = data.get("address")
        amount = data.get("amount")
        
        if not address or not amount:
            return jsonify({"error": "Address and amount are required"}), 400
        
        # Prepare BitGo API request
        bitgo_url = f"{BITGO_BASE_URL}/api/v2/tbtc/wallet/{BITGO_WALLET_ID}/sendtransaction"
        
        payload = {
            "address": address,
            "amount": str(amount),
            "walletPassphrase": BITGO_WALLET_PASSPHRASE
        }
        
        headers = {
            "Authorization": f"Bearer {BITGO_ACCESS_TOKEN}",
            "Content-Type": "application/json"
        }
        
        # Send request to BitGo
        response = requests.post(bitgo_url, json=payload, headers=headers, timeout=30)
        
        if response.status_code == 200:
            logger.info(f"Transaction successful: {response.json()}")
            return jsonify(response.json()), 200
        else:
            logger.error(f"BitGo API error: {response.status_code} - {response.text}")
            return jsonify({"error": "Transaction failed", "details": response.text}), response.status_code
            
    except Exception as e:
        logger.error(f"Send transaction error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# EXISTING WEBHOOK CODE (keep this unchanged)
@app.route("/webhook/bitgo", methods=["POST"])
def bitgo_webhook():
    # Check content type
    ctype = request.headers.get("Content-Type", "")
    if "application/json" not in ctype.lower():
        return jsonify({"error": "Unsupported media type"}), 415

    # Read raw data
    raw_body = request.get_data(cache=False, as_text=False)

    # HMAC verification
    sig = request.headers.get("X-Signature-SHA256") or request.headers.get("X-Hub-Signature-256", "")
    if not verify_hmac_sha256(raw_body, sig):
        logger.warning("Webhook signature verification failed")
        return jsonify({"error": "Invalid signature"}), 401

    # Parse JSON
    try:
        data = json.loads(raw_body.decode("utf-8") or "{}")
    except json.JSONDecodeError as e:
        return jsonify({"error": "Invalid JSON format"}), 400

    # Process webhook
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
