# src/routes/auth.py
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from src.models.user import UserManager
from src.crypto.kyber import KyberManager
from src.crypto.dilithium import DilithiumManager
from src.utils.helpers import b64encode

auth_bp = Blueprint('auth', __name__)

def get_user_manager():
    """Get UserManager instance using current app config"""
    users_file = current_app.config.get('USERS_FILE', 'data/users.json')
    return UserManager(users_file)

# src/routes/auth.py (updated)
@auth_bp.route("/register", methods=["POST"])
def register_user():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    user_manager = get_user_manager()
    
    if username in user_manager.users:
        return jsonify({"error": "Username already exists"}), 400
    
    try:
        # Generate quantum-safe keys for new user
        kem_pk, kem_sk = KyberManager.keygen()
        sig_pk, sig_sk = DilithiumManager.keygen()
        
        # Create user with encrypted private keys
        user_manager.create_user(
            username=username,
            password=password,
            kem_public_key=b64encode(kem_pk),
            sig_public_key=b64encode(sig_pk),
            kem_private_key=kem_sk,
            sig_private_key=sig_sk
        )
        
        return jsonify({
            "message": "User registered successfully",
            "public_keys": {
                "kem_public_key": b64encode(kem_pk),
                "sig_public_key": b64encode(sig_pk)
            },
            "note": "Private keys are securely encrypted and stored server-side"
        })
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@auth_bp.route("/get-private-keys", methods=["POST"])
def get_private_keys():
    """Endpoint to retrieve encrypted private keys (requires password)"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    user_manager = get_user_manager()
    
    # Verify credentials
    if not user_manager.verify_password(username, password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Get decrypted private keys
    kem_private = user_manager.get_private_key(username, password, "kem")
    sig_private = user_manager.get_private_key(username, password, "sig")
    
    if not kem_private or not sig_private:
        return jsonify({"error": "Failed to retrieve private keys"}), 500
    
    return jsonify({
        "kem_private_key": b64encode(kem_private),
        "sig_private_key": b64encode(sig_private),
        "warning": "These are your actual private keys. Store them securely and do not share!"
    })

@auth_bp.route("/login", methods=["POST"])
def login_user():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    user_manager = get_user_manager()
    user = user_manager.get_user(username)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Verify password
    if not user_manager.verify_password(username, password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Update online status
    user_manager.update_login_status(username, True)
    user = user_manager.get_user(username)
    
    # Return user public keys and info (without private keys)
    return jsonify({
        "message": "Login successful",
        "user": {
            "username": username,
            "kem_public_key": user["kem_public_key"],
            "sig_public_key": user["sig_public_key"],
            "created_at": user["created_at"],
            "is_online": user["is_online"]
        }
    })

@auth_bp.route("/logout", methods=["POST"])
def logout_user():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    username = data.get("username")
    
    if username:
        user_manager = get_user_manager()
        user_manager.update_login_status(username, False)
    
    return jsonify({"message": "Logout successful"})

@auth_bp.route("/users", methods=["GET"])
def list_users():
    """Get list of all registered users"""
    user_manager = get_user_manager()
    users = user_manager.get_all_users()
    return jsonify({"users": users})