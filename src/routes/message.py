# src/routes/message.py
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from src.crypto.kyber import KyberManager
from src.crypto.dilithium import DilithiumManager
from src.crypto.symmetric import SymmetricManager
from src.models.user import UserManager
from src.models.message import MessageManager
from src.utils.helpers import b64encode, b64decode

message_bp = Blueprint('message', __name__)


def get_user_manager():
    """Get UserManager instance using current app config"""
    users_file = current_app.config.get('USERS_FILE', 'data/users.json')
    return UserManager(users_file)


def get_message_manager():
    """Get MessageManager instance using current app config"""
    messages_file = current_app.config.get(
        'MESSAGES_FILE', 'data/messages.json')
    return MessageManager(messages_file)

# src/routes/message.py (with comprehensive debugging)


# src/routes/message.py (COMPREHENSIVE FIX)
@message_bp.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    sender = data.get("sender")
    password = data.get("password")
    recipient = data.get("recipient")
    message = data.get("message", "")

    print(
        f"DEBUG: Send message request - sender: {sender}, recipient: {recipient}")

    if not sender or not password or not recipient:
        return jsonify({"error": "Sender, password, and recipient required"}), 400

    user_manager = get_user_manager()
    message_manager = get_message_manager()

    # Verify sender credentials and get private key
    if not user_manager.verify_password(sender, password):
        return jsonify({"error": "Invalid credentials"}), 401

    sender_sig_sk = user_manager.get_private_key(sender, password, "sig")
    if not sender_sig_sk:
        return jsonify({"error": "Failed to retrieve signing key"}), 500

    # Get recipient's public key - ROBUST FIX
    recipient_user = user_manager.get_user_dict(recipient)
    if not recipient_user:
        return jsonify({"error": "Recipient not found"}), 404

    # Ensure we have a dictionary, not a Pydantic model
    if hasattr(recipient_user, 'dict'):
        # It's a Pydantic model, convert to dict
        recipient_user = recipient_user.dict()

    print(f"DEBUG: Recipient data type: {type(recipient_user)}")
    print(
        f"DEBUG: Available keys: {list(recipient_user.keys()) if isinstance(recipient_user, dict) else 'N/A'}")

    try:
        # Safe key access - handle both dict and object access
        if isinstance(recipient_user, dict):
            kem_public_key = recipient_user.get("kem_public_key")
        else:
            # Fallback to attribute access if it's an object
            kem_public_key = getattr(recipient_user, "kem_public_key", None)

        if not kem_public_key:
            return jsonify({"error": "Recipient missing KEM public key"}), 400

        recipient_kem_pk = b64decode(kem_public_key)
        message_bytes = message.encode()

        # Encrypt and sign message
        shared_key, ciphertext_kem = KyberManager.encrypt(
            message_bytes, recipient_kem_pk)
        nonce, ciphertext, tag = SymmetricManager.encrypt(
            message_bytes, shared_key)
        signature = DilithiumManager.sign(ciphertext, sender_sig_sk)

        # Prepare message data for storage
        message_data = {
            "sender": sender,
            "recipient": recipient,
            "ciphertext_kem": b64encode(ciphertext_kem),
            "ciphertext": b64encode(ciphertext),
            "nonce": b64encode(nonce),
            "tag": b64encode(tag),
            "signature": b64encode(signature),
            "timestamp": datetime.now().isoformat()
        }

        # Store the encrypted message
        message_manager.store_message(sender, recipient, message_data)

        return jsonify({
            "success": True,
            "message": "Message sent successfully",
            "data": message_data
        })
    except Exception as e:
        import traceback
        print(f"ERROR in send_message: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Message sending failed: {str(e)}"}), 500


@message_bp.route("/receive", methods=["POST"])
def receive_message():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    recipient = data.get("recipient")
    password = data.get("password")
    sender = data.get("sender")

    if not recipient or not password or not sender:
        return jsonify({"error": "Recipient, password, and sender required"}), 400

    user_manager = get_user_manager()

    # Verify recipient credentials and get private key
    if not user_manager.verify_password(recipient, password):
        return jsonify({"error": "Invalid credentials"}), 401

    recipient_kem_sk = user_manager.get_private_key(recipient, password, "kem")
    if not recipient_kem_sk:
        return jsonify({"error": "Failed to retrieve decryption key"}), 500

    # Get sender's public keys for verification - FIXED: Use get_user_dict()
    sender_user = user_manager.get_user_dict(sender)  # CHANGED HERE
    if not sender_user:
        return jsonify({"error": "Sender not found"}), 404

    try:
        # Convert message data from base64
        ciphertext_kem = b64decode(data["ciphertext_kem"])
        ciphertext = b64decode(data["ciphertext"])
        nonce = b64decode(data["nonce"])
        tag = b64decode(data["tag"])
        signature = b64decode(data["signature"])

        sender_sig_pk = b64decode(
            sender_user["sig_public_key"])  # Now this works

        # Verify signature first
        if not DilithiumManager.verify(ciphertext, signature, sender_sig_pk):
            return jsonify({"error": "Signature verification failed"}), 400

        # Decrypt the KEM ciphertext to get shared key
        shared_key = KyberManager.decrypt(ciphertext_kem, recipient_kem_sk)

        # Decrypt the symmetric ciphertext
        plaintext = SymmetricManager.decrypt(
            ciphertext, shared_key, nonce, tag)

        return jsonify({
            "success": True,
            "message": plaintext.decode(),
            "sender": sender,
            "recipient": recipient,
            "timestamp": data.get("timestamp")
        })

    except ValueError as e:
        if "MAC check failed" in str(e):
            return jsonify({"error": "Decryption failed - message not intended for this recipient or data corrupted"}), 400
        else:
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 400
    except Exception as e:
        import traceback
        print(f"Message receiving error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Message receiving failed: {str(e)}"}), 500


@message_bp.route("/history", methods=["POST"])
def get_message_history():
    """Get message history between two users"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    user1 = data.get("user1")
    user2 = data.get("user2")
    password = data.get("password")  # Require password for authentication

    if not user1 or not user2 or not password:
        return jsonify({"error": "Both users and password required"}), 400

    user_manager = get_user_manager()
    message_manager = get_message_manager()

    # Verify user credentials
    if not user_manager.verify_password(user1, password):
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        # Get encrypted message history
        encrypted_history = message_manager.get_conversation_history(
            user1, user2)

        decrypted_history = []

        for msg_data in encrypted_history:
            # Skip if this message wasn't sent to or from the requesting user
            if msg_data["sender"] != user1 and msg_data["recipient"] != user1:
                continue

            try:
                # Decrypt message if the current user is the recipient
                if msg_data["recipient"] == user1:
                    # Get private key for decryption
                    user_kem_sk = user_manager.get_private_key(
                        user1, password, "kem")
                    if not user_kem_sk:
                        continue

                    # Get sender's public key for verification - FIXED: Use get_user_dict()
                    sender_user = user_manager.get_user_dict(
                        msg_data["sender"])  # CHANGED HERE
                    if not sender_user:
                        continue

                    # Convert message data from base64
                    ciphertext_kem = b64decode(msg_data["ciphertext_kem"])
                    ciphertext = b64decode(msg_data["ciphertext"])
                    nonce = b64decode(msg_data["nonce"])
                    tag = b64decode(msg_data["tag"])
                    signature = b64decode(msg_data["signature"])

                    sender_sig_pk = b64decode(
                        sender_user["sig_public_key"])  # Now this works

                    # Verify signature
                    if not DilithiumManager.verify(ciphertext, signature, sender_sig_pk):
                        continue

                    # Decrypt the message
                    shared_key = KyberManager.decrypt(
                        ciphertext_kem, user_kem_sk)
                    plaintext = SymmetricManager.decrypt(
                        ciphertext, shared_key, nonce, tag)

                    decrypted_history.append({
                        "sender": msg_data["sender"],
                        "recipient": msg_data["recipient"],
                        "message": plaintext.decode(),
                        "timestamp": msg_data["timestamp"],
                        "isSender": msg_data["sender"] == user1
                    })
                else:
                    # Message was sent by the current user
                    decrypted_history.append({
                        "sender": msg_data["sender"],
                        "recipient": msg_data["recipient"],
                        "message": "[Encrypted message you sent]",
                        "timestamp": msg_data["timestamp"],
                        "isSender": True
                    })

            except Exception as e:
                # Skip messages that can't be decrypted
                print(f"Failed to decrypt message from history: {str(e)}")
                continue

        # Sort by timestamp
        decrypted_history.sort(key=lambda x: x["timestamp"])

        return jsonify({
            "success": True,
            "history": decrypted_history,
            "user1": user1,
            "user2": user2
        })

    except Exception as e:
        return jsonify({"error": f"Failed to retrieve message history: {str(e)}"}), 500


@message_bp.route("/conversations", methods=["POST"])
def get_user_conversations():
    """Get all conversations for a user"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user_manager = get_user_manager()
    message_manager = get_message_manager()

    # Verify user credentials
    if not user_manager.verify_password(username, password):
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        conversations = message_manager.get_user_conversations(username)
        return jsonify({
            "success": True,
            "conversations": conversations,
            "username": username
        })
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve conversations: {str(e)}"}), 500

# Add this test endpoint to message.py to verify user data types


@message_bp.route("/simple-test", methods=["GET"])
def simple_test():
    """Simple test endpoint with comprehensive debugging."""
    print("\n--- DEBUG: /simple-test endpoint initiated ---")
    
    response_data = {
        "steps": [],
        "final_status": "incomplete",
        "error_details": None
    }

    try:
        # Step 1: Initialize UserManager
        print("DEBUG: Step 1 - Initializing UserManager...")
        user_manager = get_user_manager()
        users_file = user_manager.users_file
        print(f"DEBUG: UserManager initialized with file: '{users_file}'")
        response_data["steps"].append({
            "step": "Initialize UserManager",
            "status": "success",
            "details": f"UserManager is configured to use '{users_file}'."
        })

        # Step 2: Define the test user
        test_user = "Mia859"
        print(f"DEBUG: Step 2 - Test user is set to: '{test_user}'")
        response_data["steps"].append({
            "step": "Define Test User",
            "status": "success",
            "details": f"Looking for user '{test_user}'."
        })

        # Step 3: Attempt to retrieve user as a dictionary
        print(f"DEBUG: Step 3 - Calling user_manager.get_user_dict('{test_user}')...")
        user_dict = user_manager.get_user_dict(test_user)
        
        if user_dict:
            print(f"DEBUG: Found user_dict. Type: {type(user_dict)}")
            response_data["steps"].append({
                "step": "Get User as Dictionary",
                "status": "success",
                "details": f"Found user '{test_user}'. Data type is {type(user_dict)}."
            })
        else:
            print(f"DEBUG: WARNING - User '{test_user}' not found with get_user_dict.")
            response_data["steps"].append({
                "step": "Get User as Dictionary",
                "status": "failure",
                "details": f"User '{test_user}' was not found in '{users_file}'."
            })

        # Step 4: Attempt to retrieve user as a Pydantic model
        print(f"DEBUG: Step 4 - Calling user_manager.get_user('{test_user}')...")
        user_model = user_manager.get_user(test_user)

        if user_model:
            print(f"DEBUG: Found user_model. Type: {type(user_model)}")
            response_data["steps"].append({
                "step": "Get User as Pydantic Model",
                "status": "success",
                "details": f"Found user '{test_user}'. Data type is {type(user_model)}."
            })
        else:
            print(f"DEBUG: WARNING - User '{test_user}' not found with get_user.")
            response_data["steps"].append({
                "step": "Get User as Pydantic Model",
                "status": "failure",
                "details": f"User '{test_user}' was not found in '{users_file}'."
            })

        # Final step: Report success
        response_data["final_status"] = "success"
        print("--- DEBUG: /simple-test endpoint finished successfully ---")
        return jsonify(response_data), 200

    except Exception as e:
        # Catch any unexpected errors
        import traceback
        error_message = f"An unexpected error occurred: {str(e)}"
        print(f"ERROR: {error_message}")
        print(f"Traceback: {traceback.format_exc()}")
        
        response_data["final_status"] = "error"
        response_data["error_details"] = {
            "error_type": type(e).__name__,
            "message": str(e),
            "traceback": traceback.format_exc().splitlines()
        }
        
        # Add the error to the steps for clarity
        response_data["steps"].append({
            "step": "Execution",
            "status": "error",
            "details": f"Crashed with a {type(e).__name__}."
        })
        
        print("--- DEBUG: /simple-test endpoint failed with an exception ---")
        return jsonify(response_data), 500