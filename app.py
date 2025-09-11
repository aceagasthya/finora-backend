from flask import Flask, request, jsonify
import json
from datetime import datetime
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route("/")
def home():
    return "Finora backend is running 🚀"

@app.route("/webhook/bitgo", methods=["POST"])
def bitgo_webhook():
    try:
        data = request.json
        logger.info(f"Webhook received: {data}")
        
        if data.get('type') == 'transfer' and data.get('state') == 'confirmed':
            logger.info("💰 Deposit confirmed!")
            value = data.get('value', {})
            logger.info(f"Amount: {value.get('amount')}")
            logger.info(f"Currency: {value.get('currency')}")
            logger.info(f"Transaction ID: {data.get('hash')}")
        
        return jsonify({"status": "OK"}), 200
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({"error": "Internal error"}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=10000, debug=False)
