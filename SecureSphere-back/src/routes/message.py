# src/routes/message.py (COMPLETE WITH JWT)
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from src.crypto.kyber import KyberManager
from src.crypto.dilithium import DilithiumManager
from src.crypto.symmetric import SymmetricManager
from src.models.user import UserManager
from src.models.message import MessageManager
from src.utils.helpers import b64encode, b64decode
from src.middleware.auth import token_required
from src.utils.jwt_utils import JWTManager # Import JWTManager

message_bp = Blueprint('message', __name__)

def get_user_manager():
    """Get UserManager instance using current app config"""
    users_file = current_app.config.get('USERS_FILE', 'data/users.json')
    return UserManager(users_file)

def get_message_manager():
    """Get MessageManager instance using current app config"""
    messages_file = current_app.config.get('MESSAGES_FILE', 'data/messages.json')
    return MessageManager(messages_file)

def get_token_from_header():
    """Helper to extract the token from the Authorization header."""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header.split(' ')[1]
    return None

@message_bp.route("/send", methods=["POST"])
@token_required
def send_message():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    sender = request.username  # Get from JWT token
    recipient = data.get("recipient")
    message = data.get("message", "")

    print(f"DEBUG: Send message request - sender: {sender}, recipient: {recipient}")

    if not recipient:
        return jsonify({"error": "Recipient required"}), 400

    user_manager = get_user_manager()
    message_manager = get_message_manager()

    # --- FIX START ---
    # Retrieve private keys from the JWT token instead of decrypting from storage
    token = get_token_from_header()
    if not token:
        return jsonify({"error": "Authorization token not found"}), 401

    private_keys = JWTManager.extract_private_keys(token)
    if not private_keys or 'sig_private' not in private_keys:
        return jsonify({"error": "Failed to retrieve signing key from token"}), 500
    
    sender_sig_sk = b64decode(private_keys['sig_private'])
    # --- FIX END ---

    # Get recipient's public key
    recipient_user = user_manager.get_user_dict(recipient)
    if not recipient_user:
        return jsonify({"error": "Recipient not found"}), 404

    # Ensure we have a dictionary, not a Pydantic model
    if hasattr(recipient_user, 'dict'):
        recipient_user = recipient_user.dict()

    print(f"DEBUG: Recipient data type: {type(recipient_user)}")
    print(f"DEBUG: Available keys: {list(recipient_user.keys()) if isinstance(recipient_user, dict) else 'N/A'}")

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
        shared_key, ciphertext_kem = KyberManager.encrypt(message_bytes, recipient_kem_pk)
        nonce, ciphertext, tag = SymmetricManager.encrypt(message_bytes, shared_key)
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
        conversation_id = message_manager.store_message(sender, recipient, message_data)

        return jsonify({
            "success": True,
            "message": "Message sent successfully",
            "data": message_data,
            "conversation_id": conversation_id
        })
    except Exception as e:
        import traceback
        print(f"ERROR in send_message: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Message sending failed: {str(e)}"}), 500

@message_bp.route("/receive", methods=["POST"])
@token_required
def receive_message():
    """Receive and decrypt a specific message"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    recipient = request.username  # Get from JWT token
    sender = data.get("sender")
    message_data = data.get("message_data")

    if not sender or not message_data:
        return jsonify({"error": "Sender and message data required"}), 400

    user_manager = get_user_manager()

    # --- FIX START ---
    # Get recipient's private key for decryption from the JWT token
    token = get_token_from_header()
    if not token:
        return jsonify({"error": "Authorization token not found"}), 401

    private_keys = JWTManager.extract_private_keys(token)
    if not private_keys or 'kem_private' not in private_keys:
        return jsonify({"error": "Failed to retrieve decryption key from token"}), 500

    recipient_kem_sk = b64decode(private_keys['kem_private'])
    # --- FIX END ---

    # Get sender's public keys for verification
    sender_user = user_manager.get_user_dict(sender)
    if not sender_user:
        return jsonify({"error": "Sender not found"}), 404

    try:
        # Convert message data from base64
        ciphertext_kem = b64decode(message_data["ciphertext_kem"])
        ciphertext = b64decode(message_data["ciphertext"])
        nonce = b64decode(message_data["nonce"])
        tag = b64decode(message_data["tag"])
        signature = b64decode(message_data["signature"])

        sender_sig_pk = b64decode(sender_user["sig_public_key"])

        # Verify signature first
        if not DilithiumManager.verify(ciphertext, signature, sender_sig_pk):
            return jsonify({"error": "Signature verification failed"}), 400

        # Decrypt the KEM ciphertext to get shared key
        shared_key = KyberManager.decrypt(ciphertext_kem, recipient_kem_sk)

        # Decrypt the symmetric ciphertext
        plaintext = SymmetricManager.decrypt(ciphertext, shared_key, nonce, tag)

        return jsonify({
            "success": True,
            "message": plaintext.decode(),
            "sender": sender,
            "recipient": recipient,
            "timestamp": message_data.get("timestamp")
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
@token_required
def get_message_history():
    """Get message history between two users"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    user1 = request.username  # Get from JWT token
    user2 = data.get("user2")

    if not user2:
        return jsonify({"error": "Other user required"}), 400

    user_manager = get_user_manager()
    message_manager = get_message_manager()
    
    # --- FIX START ---
    # Get private key for decryption from the JWT token
    token = get_token_from_header()
    if not token:
        return jsonify({"error": "Authorization token not found"}), 401
        
    private_keys = JWTManager.extract_private_keys(token)
    user_kem_sk = None
    if private_keys and 'kem_private' in private_keys:
        user_kem_sk = b64decode(private_keys['kem_private'])
    
    if not user_kem_sk:
        # Return an error or handle gracefully if key is missing
        # For history, we can proceed but won't be able to decrypt received messages
        print("WARN: KEM private key not in token. Will not be able to decrypt received messages in history.")
    # --- FIX END ---
    
    try:
        # Get encrypted message history
        encrypted_history = message_manager.get_conversation_history(user1, user2)

        decrypted_history = []

        for msg_data in encrypted_history:
            # Skip if this message wasn't sent to or from the requesting user
            if msg_data["sender"] != user1 and msg_data["recipient"] != user1:
                continue

            try:
                # Decrypt message if the current user is the recipient and we have the key
                if msg_data["recipient"] == user1 and user_kem_sk:
                    # Get sender's public key for verification
                    sender_user = user_manager.get_user_dict(msg_data["sender"])
                    if not sender_user:
                        continue

                    # Convert message data from base64
                    ciphertext_kem = b64decode(msg_data["ciphertext_kem"])
                    ciphertext = b64decode(msg_data["ciphertext"])
                    nonce = b64decode(msg_data["nonce"])
                    tag = b64decode(msg_data["tag"])
                    signature = b64decode(msg_data["signature"])

                    sender_sig_pk = b64decode(sender_user["sig_public_key"])

                    # Verify signature
                    if not DilithiumManager.verify(ciphertext, signature, sender_sig_pk):
                        continue

                    # Decrypt the message
                    shared_key = KyberManager.decrypt(ciphertext_kem, user_kem_sk)
                    plaintext = SymmetricManager.decrypt(ciphertext, shared_key, nonce, tag)

                    decrypted_history.append({
                        "id": f"msg_{len(decrypted_history)}",
                        "sender": msg_data["sender"],
                        "recipient": msg_data["recipient"],
                        "message": plaintext.decode(),
                        "timestamp": msg_data["timestamp"],
                        "isSender": msg_data["sender"] == user1
                    })
                else:
                    # Message was sent by the current user OR we can't decrypt
                    is_sender = msg_data["sender"] == user1
                    message_text = "[Your sent message]" if is_sender else "[Encrypted message]"
                    error_code = None if is_sender else "decryption_key_unavailable"

                    decrypted_history.append({
                        "id": f"msg_{len(decrypted_history)}",
                        "sender": msg_data["sender"],
                        "recipient": msg_data["recipient"],
                        "message": message_text,
                        "timestamp": msg_data["timestamp"],
                        "isSender": is_sender,
                        "error": error_code
                    })

            except Exception as e:
                # Skip messages that can't be decrypted
                print(f"Failed to decrypt message from history: {str(e)}")
                # Add encrypted message as placeholder
                decrypted_history.append({
                    "id": f"msg_{len(decrypted_history)}",
                    "sender": msg_data["sender"],
                    "recipient": msg_data["recipient"],
                    "message": "[Encrypted message]",
                    "timestamp": msg_data["timestamp"],
                    "isSender": msg_data["sender"] == user1,
                    "error": "decryption_failed"
                })
                continue

        # Sort by timestamp
        decrypted_history.sort(key=lambda x: x["timestamp"])

        return jsonify({
            "success": True,
            "history": decrypted_history,
            "user1": user1,
            "user2": user2,
            "count": len(decrypted_history)
        })

    except Exception as e:
        import traceback
        print(f"Error in get_message_history: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Failed to retrieve message history: {str(e)}"}), 500

# (The rest of the file remains the same)

@message_bp.route("/conversations", methods=["GET"])
@token_required
def get_user_conversations():
    """Get all conversations for a user"""
    username = request.username  # Get from JWT token

    user_manager = get_user_manager()
    message_manager = get_message_manager()

    try:
        conversations = message_manager.get_user_conversations(username)
        
        # Enhance conversations with user details
        enhanced_conversations = []
        for conv in conversations:
            other_user = user_manager.get_user_dict(conv['other_user'])
            if other_user:
                # Convert to dict if it's a Pydantic model
                if hasattr(other_user, 'dict'):
                    other_user = other_user.dict()
                
                enhanced_conv = {
                    'other_user': conv['other_user'],
                    'conversation_id': conv['conversation_id'],
                    'last_message': conv['last_message'],
                    'message_count': conv['message_count'],
                    'last_updated': conv['last_updated'],
                    'user_details': {
                        'username': other_user.get('username'),
                        'email': other_user.get('email'),
                        'is_online': other_user.get('is_online', False),
                        'last_seen': other_user.get('last_seen')
                    }
                }
                enhanced_conversations.append(enhanced_conv)

        return jsonify({
            "success": True,
            "conversations": enhanced_conversations,
            "username": username
        })
    except Exception as e:
        import traceback
        print(f"Error in get_user_conversations: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Failed to retrieve conversations: {str(e)}"}), 500

@message_bp.route("/conversations", methods=["POST"])
@token_required
def get_user_conversations_post():
    """Get all conversations for a user (POST method for consistency)"""
    return get_user_conversations()

@message_bp.route("/delete", methods=["POST"])
@token_required
def delete_message():
    """Delete a specific message (placeholder implementation)"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    message_id = data.get("message_id")
    # Implementation would depend on your message storage structure
    
    return jsonify({
        "success": True,
        "message": "Message deletion endpoint - implement based on storage needs"
    })

@message_bp.route("/clear-conversation", methods=["POST"])
@token_required
def clear_conversation():
    """Clear all messages in a conversation"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    user1 = request.username
    user2 = data.get("user2")

    if not user2:
        return jsonify({"error": "Other user required"}), 400

    # This would require modifying the MessageManager to support deletion
    # For now, return a placeholder response
    
    return jsonify({
        "success": True,
        "message": f"Conversation between {user1} and {user2} would be cleared",
        "note": "Implementation needed in MessageManager"
    })

@message_bp.route("/search", methods=["POST"])
@token_required
def search_messages():
    """Search messages in conversations"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    query = data.get("query", "").lower()
    username = request.username

    if not query:
        return jsonify({"error": "Search query required"}), 400

    user_manager = get_user_manager()
    message_manager = get_message_manager()

    try:
        # Get all conversations for the user
        conversations = message_manager.get_user_conversations(username)
        search_results = []

        for conv in conversations:
            # Get message history for this conversation
            history = message_manager.get_conversation_history(username, conv['other_user'])
            
            for msg_data in history:
                # For now, we can only search in messages we sent
                # To search in received messages, we'd need to decrypt them all
                if msg_data["sender"] == username:
                    # This is where we'd decrypt and search if we stored plaintext
                    # For now, return basic message info
                    search_results.append({
                        "conversation_with": conv['other_user'],
                        "timestamp": msg_data["timestamp"],
                        "preview": "[Encrypted message content]",
                        "is_sent": True
                    })

        return jsonify({
            "success": True,
            "results": search_results,
            "query": query,
            "count": len(search_results)
        })

    except Exception as e:
        import traceback
        print(f"Error in search_messages: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Search failed: {str(e)}"}), 500

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

@message_bp.route("/status", methods=["GET"])
@token_required
def message_status():
    """Get message service status"""
    username = request.username
    
    user_manager = get_user_manager()
    message_manager = get_message_manager()
    
    try:
        # Get basic stats
        conversations = message_manager.get_user_conversations(username)
        total_messages = sum(conv['message_count'] for conv in conversations)
        
        return jsonify({
            "success": True,
            "status": "operational",
            "user": username,
            "stats": {
                "total_conversations": len(conversations),
                "total_messages": total_messages,
                "last_active": datetime.now().isoformat()
            },
            "crypto": {
                "kem_algorithm": current_app.config.get('KEM_ALGORITHM', 'Kyber512'),
                "sig_algorithm": current_app.config.get('SIG_ALGORITHM', 'Dilithium2'),
                "symmetric_algorithm": current_app.config.get('SYMMETRIC_ALGORITHM', 'AES-GCM')
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Status check failed: {str(e)}"
        }), 500

# Health check endpoint
@message_bp.route("/health", methods=["GET"])
def health_check():
    """Message service health check"""
    try:
        user_manager = get_user_manager()
        message_manager = get_message_manager()
        
        # Basic functionality test
        test_user = list(user_manager.users.keys())[0] if user_manager.users else "test"
        conversations = message_manager.get_user_conversations(test_user)
        
        return jsonify({
            "status": "healthy",
            "service": "message",
            "users_count": len(user_manager.users),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "service": "message",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500