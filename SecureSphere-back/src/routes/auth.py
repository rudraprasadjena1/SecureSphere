# src/routes/auth.py - Enhanced with token management and private key storage
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from src.models.user import UserManager
from src.crypto.kyber import KyberManager
from src.crypto.dilithium import DilithiumManager
from src.utils.helpers import b64encode
from src.utils.jwt_utils import JWTManager
from src.middleware.auth import token_required, get_token_blacklist
import jwt

auth_bp = Blueprint('auth', __name__)

def get_user_manager():
    """Get UserManager instance using current app config"""
    users_file = current_app.config.get('USERS_FILE', 'data/users.json')
    return UserManager(users_file)

@auth_bp.route("/register", methods=["POST"])
def register_user():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    # Generate a default email if not provided
    if not email:
        email = f"{username}@example.com"
    
    user_manager = get_user_manager()
    
    if username in user_manager.users:
        return jsonify({"error": "Username already exists"}), 400
    
    try:
        # Generate quantum-safe keys for new user
        kem_pk, kem_sk = KyberManager.keygen()
        sig_pk, sig_sk = DilithiumManager.keygen()
        
        user_manager.create_user(
            username=username,
            email=email,
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
        import traceback
        print(f"Registration error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

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
    
    # Verify credentials using internal method for password check
    if not user_manager.verify_password(username, password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    try:
        # Get user as Pydantic model
        user_model = user_manager.get_user(username)
        if not user_model:
            return jsonify({"error": "User not found"}), 404
        
        # Decrypt private keys using the password
        kem_private_key = user_manager.get_private_key(username, password, 'kem')
        sig_private_key = user_manager.get_private_key(username, password, 'sig')
        
        if not kem_private_key or not sig_private_key:
            return jsonify({"error": "Failed to decrypt private keys"}), 500
        
        # Encode private keys as base64 for storage in JWT
        private_keys = {
            'kem_private': b64encode(kem_private_key),
            'sig_private': b64encode(sig_private_key)
        }
        
        # Update online status
        user_manager.update_login_status(username, True)
        
        # Generate JWT tokens with private keys embedded
        access_token = JWTManager.generate_access_token(
            user_model.id, 
            user_model.username, 
            user_model.email,
            private_keys=private_keys  # Add private keys to token
        )
        refresh_token = JWTManager.generate_refresh_token(user_model.id)
        
        # Generate token fingerprint for tracking
        token_fingerprint = JWTManager.get_token_fingerprint(access_token)
        
        # Return user public keys and info with tokens
        return jsonify({
            "message": "Login successful",
            "tokens": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds(),
                "fingerprint": token_fingerprint
            },
            "user": {
                "username": user_model.username,
                "email": user_model.email,
                "kem_public_key": user_model.kem_public_key,
                "sig_public_key": user_model.sig_public_key,
                "created_at": user_model.created_at,
                "is_online": user_model.is_online,
                "last_seen": user_model.last_seen
            }
        })
    except Exception as e:
        import traceback
        print(f"Login error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

@auth_bp.route("/refresh", methods=["POST"])
def refresh_token():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    refresh_token_str = data.get("refresh_token")
    
    if not refresh_token_str:
        return jsonify({"error": "Refresh token required"}), 400
    
    # Check if refresh token is blacklisted
    blacklist = get_token_blacklist()
    if blacklist.is_blacklisted(refresh_token_str):
        return jsonify({"error": "Refresh token has been revoked"}), 401
    
    # Generate new access token
    # Note: New access token won't have private keys without password
    # User needs to login again for full functionality
    new_access_token = JWTManager.refresh_access_token(refresh_token_str)
    if not new_access_token:
        return jsonify({"error": "Invalid refresh token"}), 401
    
    return jsonify({
        "access_token": new_access_token,
        "token_type": "bearer",
        "expires_in": current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds(),
        "note": "For full functionality, please login again to reload private keys"
    })

@auth_bp.route("/logout", methods=["POST"])
@token_required
def logout_user():
    """Logout user and blacklist tokens"""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        
        # Decode token to get expiration
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            expires_at = datetime.fromtimestamp(payload['exp']).isoformat()
            
            # Add to blacklist
            blacklist = get_token_blacklist()
            blacklist.add_token(
                token, 
                request.user_id, 
                expires_at, 
                "logout"
            )
            
        except Exception as e:
            print(f"Error blacklisting token: {e}")
    
    # Update user status
    user_manager = get_user_manager()
    user_manager.update_login_status(request.username, False)
    
    return jsonify({"message": "Logout successful"})

@auth_bp.route("/logout-all", methods=["POST"])
@token_required
def logout_all_sessions():
    """Logout from all sessions (blacklist all user tokens)"""
    # This would require tracking all active tokens per user
    # For now, this is a placeholder implementation
    user_manager = get_user_manager()
    user_manager.update_login_status(request.username, False)
    
    return jsonify({
        "message": "Logged out from all sessions",
        "note": "Full session management implementation needed"
    })

@auth_bp.route("/tokens/inspect", methods=["POST"])
@token_required
def inspect_token():
    """Inspect current token (for debugging)"""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        
        # Decode without verification for inspection
        decoded = JWTManager.decode_token_without_verification(token)
        
        # Remove sensitive private keys from output
        if 'private_keys' in decoded:
            decoded['private_keys'] = {
                'kem_private': '[REDACTED]',
                'sig_private': '[REDACTED]'
            }
        
        return jsonify({
            "token_info": {
                "fingerprint": JWTManager.get_token_fingerprint(token),
                "decoded_payload": decoded,
                "length": len(token),
                "has_private_keys": 'private_keys' in decoded
            }
        })
    
    return jsonify({"error": "No token provided"}), 400

@auth_bp.route("/tokens/generate-api-key", methods=["POST"])
@token_required
def generate_api_key():
    """Generate API key for programmatic access"""
    permissions = request.json.get('permissions', ['read', 'write'])
    
    # API keys don't include private keys for security
    api_key = JWTManager.generate_api_key(
        request.user_id, 
        request.username, 
        permissions
    )
    
    return jsonify({
        "api_key": api_key,
        "permissions": permissions,
        "expires_in": "1 year",
        "warning": "Store this securely - it will not be shown again",
        "note": "API keys do not include private keys. Use user login for full encryption features."
    })

@auth_bp.route("/me", methods=["GET"])
@token_required
def get_current_user():
    """Get current user info"""
    user_manager = get_user_manager()
    user_model = user_manager.get_user(request.username)
    
    if not user_model:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "user": {
            "username": user_model.username,
            "email": user_model.email,
            "kem_public_key": user_model.kem_public_key,
            "sig_public_key": user_model.sig_public_key,
            "created_at": user_model.created_at,
            "is_online": user_model.is_online,
            "last_seen": user_model.last_seen,
            "has_private_keys_loaded": hasattr(request, 'private_keys') and request.private_keys is not None
        }
    })

@auth_bp.route("/users", methods=["GET"])
@token_required
def list_users():
    """Get list of all registered users"""
    user_manager = get_user_manager()
    all_users = user_manager.get_all_users()
    
    # Return users without sensitive data
    users_list = [
        {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_online': user.is_online,
            'last_seen': user.last_seen
        }
        for user in all_users
        if user.username != request.username  # Exclude current user
    ]
    
    return jsonify({
        "users": users_list,
        "count": len(users_list)
    })

@auth_bp.route("/check-username", methods=["POST"])
def check_username():
    data = request.get_json()
    if not data or "username" not in data:
        return jsonify({"error": "Username not provided"}), 400
        
    username = data.get("username")
    user_manager = get_user_manager()
    
    if username in user_manager.users:
        return jsonify({"available": False})
    else:
        return jsonify({"available": True})

@auth_bp.route("/tokens/cleanup", methods=["POST"])
def cleanup_tokens():
    """Clean up expired blacklisted tokens (admin function)"""
    blacklist = get_token_blacklist()
    initial_count = len(blacklist.blacklist)
    
    blacklist.cleanup_expired()
    
    return jsonify({
        "message": "Token cleanup completed",
        "removed_count": initial_count - len(blacklist.blacklist),
        "remaining_count": len(blacklist.blacklist)
    })