import os
import hmac
import hashlib
import json
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# 1) Limits and basic hardening
# Cap request size (default 1 MB). Change via env MAX_CONTENT_LENGTH if needed.
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 1024 * 1024))

# 2) Logging (keep concise; gunicorn provides access logs)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("finora")

# 3) Optional HMAC verification (set WEBHOOK_HMAC_SECRET in Render to enable)
HMAC_SECRET = os.environ.get("WEBHOOK_HMAC_SECRET", "").strip()

def verify_hmac_sha256(raw_body: bytes, received_sig: str) -> bool:
    """
    Compare hex SHA-256 HMAC of raw_body with received signature.
    Adjust if the provider uses a different header or encoding (e.g., 'sha256=...').
    """
    if not HMAC_SECRET:
        return True  # signature check disabled
    if not received_sig:
        return False
    # Normalize header formats like "sha256=<hex>"
    if "=" in received_sig:
        _, received_sig = received_sig.split("=", 1)
    computed = hmac.new(HMAC_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed.lower(), received_sig.strip().lower())

@app.route("/", methods=["GET"])
def home():
    return "Finora backend is running 🚀"

@app.route("/health", methods=["GET"])
def health():
    return {
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat()
    }, 200

@app.route("/webhook/bitgo", methods=["POST"])
def bitgo_webhook():
    # Enforce JSON content type
    ctype = request.headers.get("Content-Type", "")
    if "application/json" not in ctype.lower():
        return jsonify({"error": "Unsupported media type; send application/json"}), 415

    # Extra size guard (Werkzeug also enforces MAX_CONTENT_LENGTH)
    if request.content_length and request.content_length > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": "Payload too large"}), 413

    # Read raw bytes once (needed for HMAC)
    raw_body = request.get_data(cache=False, as_text=False)

    # Optional signature verification (set the correct header for your sender)
    sig = request.headers.get("X-Signature-SHA256") or request.headers.get("X-Hub-Signature-256", "")
    if not verify_hmac_sha256(raw_body, sig):
        logger.warning("Webhook signature verification failed")
        return jsonify({"error": "Invalid signature"}), 401

    # Parse JSON
    try:
        data = json.loads(raw_body.decode("utf-8") or "{}")
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error: {e}")
        return jsonify({"error": "Invalid JSON format"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    # Concise structured log (avoid logging secrets)
    wtype = data.get("type")
    state = data.get("state")
    logger.info(f"Webhook received type={wtype} state={state}")

    # Handle events
    if wtype == "transfer" and state == "confirmed":
        value = data.get("value", {}) or {}
        amount = value.get("amount")
        currency = value.get("currency")
        txid = data.get("hash")
        logger.info(f"Deposit confirmed amount={amount} currency={currency} txid={txid}")
        # TODO: enqueue async job or DB update here
    elif wtype == "wallet_confirmation":
        logger.info("Wallet confirmation received")
    elif wtype == "block":
        logger.info("New block notification")
    else:
        logger.info(f"Other webhook type: {wtype}")

    # Return quickly to prevent retries by sender
    return jsonify({"status": "OK"}), 200

# Local development only (Render uses gunicorn to serve app:app)
if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "4000"))
    app.run(host=host, port=port, debug=False)