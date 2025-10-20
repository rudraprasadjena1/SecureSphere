# src/routes/message.py
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from src.crypto.kyber import KyberManager
from src.crypto.dilithium import DilithiumManager
from src.crypto.symmetric import SymmetricManager
from src.models.user import UserManager
from src.utils.helpers import b64encode, b64decode

message_bp = Blueprint('message', __name__)

def get_user_manager():
    """Get UserManager instance using current app config"""
    users_file = current_app.config.get('USERS_FILE', 'data/users.json')
    return UserManager(users_file)

@message_bp.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    sender = data.get("sender")
    password = data.get("password")  # Require password for signing
    recipient = data.get("recipient")
    message = data.get("message", "")
    
    if not sender or not password or not recipient:
        return jsonify({"error": "Sender, password, and recipient required"}), 400
    
    user_manager = get_user_manager()
    
    # Verify sender credentials and get private key
    if not user_manager.verify_password(sender, password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    sender_sig_sk = user_manager.get_private_key(sender, password, "sig")
    if not sender_sig_sk:
        return jsonify({"error": "Failed to retrieve signing key"}), 500
    
    # Get recipient's public key
    recipient_user = user_manager.get_user(recipient)
    if not recipient_user:
        return jsonify({"error": "Recipient not found"}), 404
    
    try:
        recipient_kem_pk = b64decode(recipient_user["kem_public_key"])
        message_bytes = message.encode()
        
        # Encrypt and sign message
        shared_key, ciphertext_kem = KyberManager.encrypt(message_bytes, recipient_kem_pk)
        nonce, ciphertext, tag = SymmetricManager.encrypt(message_bytes, shared_key)
        signature = DilithiumManager.sign(ciphertext, sender_sig_sk)
        
        return jsonify({
            "sender": sender,
            "recipient": recipient,
            "ciphertext_kem": b64encode(ciphertext_kem),
            "ciphertext": b64encode(ciphertext),
            "nonce": b64encode(nonce),
            "tag": b64encode(tag),
            "signature": b64encode(signature),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": f"Message sending failed: {str(e)}"}), 500


# src/routes/message.py (update receive_message function)
@message_bp.route("/receive", methods=["POST"])
def receive_message():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    recipient = data.get("recipient")
    password = data.get("password")  # Require password for decryption
    sender = data.get("sender")
    
    if not recipient or not password or not sender:
        return jsonify({"error": "Recipient, password, and sender required"}), 400
    
    user_manager = get_user_manager()
    
    # Verify recipient credentials and get private key
    if not user_manager.verify_password(recipient, password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    recipient_kem_sk = user_manager.get_private_key(recipient, password, "kem")
    if not recipient_kem_sk:
        return jsonify({"error": "Failed to retrieve decryption key - check password or key storage"}), 500
    
    # Get sender's public keys for verification
    sender_user = user_manager.get_user(sender)
    if not sender_user:
        return jsonify({"error": "Sender not found"}), 404
    
    try:
        # Convert message data from base64
        ciphertext_kem = b64decode(data["ciphertext_kem"])
        ciphertext = b64decode(data["ciphertext"])
        nonce = b64decode(data["nonce"])
        tag = b64decode(data["tag"])
        signature = b64decode(data["signature"])
        
        sender_sig_pk = b64decode(sender_user["sig_public_key"])
        
        # Verify signature first (cheaper operation)
        if not DilithiumManager.verify(ciphertext, signature, sender_sig_pk):
            return jsonify({"error": "Signature verification failed"}), 400
        
        # Decrypt the KEM ciphertext to get shared key
        shared_key = KyberManager.decrypt(ciphertext_kem, recipient_kem_sk)
        
        # Decrypt the symmetric ciphertext
        plaintext = SymmetricManager.decrypt(ciphertext, shared_key, nonce, tag)
        
        return jsonify({
            "message": plaintext.decode(),
            "sender": sender,
            "recipient": recipient,
            "timestamp": data.get("timestamp")
        })
        
    except ValueError as e:
        # This catches MAC check failures and other decryption errors
        if "MAC check failed" in str(e):
            return jsonify({"error": "Decryption failed - message not intended for this recipient or data corrupted"}), 400
        else:
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 400
    except Exception as e:
        # Catch any other unexpected errors
        import traceback
        print(f"Message receiving error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Message receiving failed: {str(e)}"}), 500