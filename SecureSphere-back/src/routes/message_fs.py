# src/routes/message_fs.py
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from src.crypto.forward_secrecy import PerMessageFSManager
from src.models.user import UserManager
from src.models.message import MessageManager
from src.utils.helpers import b64encode, b64decode
from src.middleware.auth import token_required
from src.utils.jwt_utils import JWTManager

message_fs_bp = Blueprint('message_fs', __name__)

def get_user_manager():
    users_file = current_app.config.get('USERS_FILE', 'data/users.json')
    return UserManager(users_file)

def get_message_manager():
    messages_file = current_app.config.get('MESSAGES_FILE', 'data/messages.json')
    return MessageManager(messages_file)

@message_fs_bp.route("/send-per-message-fs", methods=["POST"])
@token_required
def send_per_message_fs():
    """
    Send message with PER-MESSAGE forward secrecy
    Each message gets fresh X25519 + fresh Kyber encapsulation
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    sender = request.username
    recipient = data.get("recipient")
    message = data.get("message", "")

    if not recipient:
        return jsonify({"error": "Recipient required"}), 400

    user_manager = get_user_manager()
    message_manager = get_message_manager()

    # Get signing key from JWT token
    token = get_token_from_header()
    private_keys = JWTManager.extract_private_keys(token)
    if not private_keys or 'sig_private' not in private_keys:
        return jsonify({"error": "Failed to retrieve signing key from token"}), 500
    
    sender_sig_sk = b64decode(private_keys['sig_private'])

    # Get recipient's PUBLIC keys only
    recipient_user = user_manager.get_user_dict(recipient)
    if not recipient_user:
        return jsonify({"error": "Recipient not found"}), 404

    try:
        recipient_kem_pk = b64decode(recipient_user["kem_public_key"])
        recipient_ecdh_pk = b64decode(recipient_user["ecdh_public_key"])
        message_bytes = message.encode()

        # Encrypt with PER-MESSAGE forward secrecy
        encrypted_data = PerMessageFSManager.encrypt_single_message(
            plaintext=message_bytes,
            recipient_kem_pub=recipient_kem_pk,
            recipient_ecdh_static_pub=recipient_ecdh_pk,
            sender_sig_sk=sender_sig_sk
        )

        # Prepare message data
        message_data = {
            "sender": sender,
            "recipient": recipient,
            "ciphertext_kem": PerMessageFSManager.b64e(encrypted_data['ciphertext_kem']),
            "ciphertext": PerMessageFSManager.b64e(encrypted_data['ciphertext']),
            "nonce": PerMessageFSManager.b64e(encrypted_data['nonce']),
            "tag": PerMessageFSManager.b64e(encrypted_data['tag']),
            "signature": PerMessageFSManager.b64e(encrypted_data['signature']),
            "ephemeral_public_key": PerMessageFSManager.b64e(encrypted_data['ephemeral_public_key']),
            "message_id": encrypted_data['message_id'],
            "timestamp": datetime.now().isoformat(),
            "version": "2.0-per-message-fs",
            "algorithm": "Kyber512-X25519-Per-Message-FS"
        }

        # Store message
        conversation_id = message_manager.store_message(sender, recipient, message_data)

        return jsonify({
            "success": True,
            "message": "Per-message forward secret message sent",
            "message_id": encrypted_data['message_id'],
            "conversation_id": conversation_id,
            "security_properties": PerMessageFSManager.get_security_properties(),
            "ephemeral_key_generated": True  # Confirming fresh key for this message
        })

    except Exception as e:
        import traceback
        print(f"ERROR in send_per_message_fs: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Per-message FS failed: {str(e)}"}), 500

@message_fs_bp.route("/receive-per-message-fs", methods=["POST"])
@token_required
def receive_per_message_fs():
    """Receive per-message forward secret message"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    recipient = request.username
    sender = data.get("sender")
    message_data = data.get("message_data")

    if not sender or not message_data:
        return jsonify({"error": "Sender and message data required"}), 400

    user_manager = get_user_manager()

    # Get recipient's private keys
    token = get_token_from_header()
    private_keys = JWTManager.extract_private_keys(token)
    if not private_keys:
        return jsonify({"error": "Failed to retrieve private keys from token"}), 500
    
    recipient_kem_sk = b64decode(private_keys['kem_private'])
    recipient_ecdh_sk = b64decode(private_keys.get('ecdh_private', ''))
    
    if not recipient_ecdh_sk:
        return jsonify({"error": "ECDH private key not available"}), 500

    # Get sender's public key for verification
    sender_user = user_manager.get_user_dict(sender)
    if not sender_user:
        return jsonify({"error": "Sender not found"}), 404

    try:
        # Convert from base64
        encrypted_data = {
            'ciphertext_kem': PerMessageFSManager.b64d(message_data["ciphertext_kem"]),
            'ciphertext': PerMessageFSManager.b64d(message_data["ciphertext"]),
            'nonce': PerMessageFSManager.b64d(message_data["nonce"]),
            'tag': PerMessageFSManager.b64d(message_data["tag"]),
            'signature': PerMessageFSManager.b64d(message_data["signature"]),
            'ephemeral_public_key': PerMessageFSManager.b64d(message_data["ephemeral_public_key"])
        }

        sender_sig_pk = PerMessageFSManager.b64d(sender_user["sig_public_key"])

        # Decrypt with per-message FS
        plaintext = PerMessageFSManager.decrypt_single_message(
            encrypted_data=encrypted_data,
            recipient_kem_priv=recipient_kem_sk,
            recipient_ecdh_static_priv=recipient_ecdh_sk,
            sender_sig_pub=sender_sig_pk
        )

        return jsonify({
            "success": True,
            "message": plaintext.decode(),
            "sender": sender,
            "recipient": recipient,
            "message_id": message_data.get("message_id"),
            "timestamp": message_data.get("timestamp"),
            "security_properties": PerMessageFSManager.get_security_properties(),
            "ephemeral_key_used": True  # Confirming per-message ephemeral key was used
        })

    except ValueError as e:
        error_msg = str(e)
        if "Signature verification failed" in error_msg:
            return jsonify({"error": "Message authentication failed"}), 400
        elif "MAC check failed" in error_msg:
            return jsonify({"error": "Decryption failed - message corrupted"}), 400
        else:
            return jsonify({"error": f"Decryption failed: {error_msg}"}), 400
    except Exception as e:
        import traceback
        print(f"Per-message FS receive error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Message receive failed: {str(e)}"}), 500

@message_fs_bp.route("/security-properties", methods=["GET"])
def get_security_properties():
    """Get detailed security properties of the per-message FS scheme"""
    return jsonify({
        "security_scheme": "per_message_hybrid_forward_secrecy",
        "properties": PerMessageFSManager.get_security_properties(),
        "benefits": [
            "Each message has independent cryptographic protection",
            "Compromise of one message doesn't affect other messages", 
            "Fresh ephemeral X25519 key for every message",
            "Fresh Kyber encapsulation for every message",
            "Post-quantum secure with classical forward secrecy",
            "Strong authentication via Dilithium signatures"
        ],
        "comparison": {
            "traditional_session_fs": "Forward secrecy at session level",
            "per_message_fs": "Forward secrecy at individual message level",
            "security_level": "Enhanced - each message is cryptographically isolated"
        }
    })