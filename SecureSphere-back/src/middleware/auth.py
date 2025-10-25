# src/middleware/auth.py - Enhanced with blacklist
from functools import wraps
from flask import request, jsonify, current_app
from src.utils.jwt_utils import JWTManager
from src.models.token_blacklist import TokenBlacklist

def get_token_blacklist():
    """Get TokenBlacklist instance"""
    blacklist_file = current_app.config.get('TOKEN_BLACKLIST_FILE', 'data/token_blacklist.json')
    return TokenBlacklist(blacklist_file)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({"error": "Authentication token is required"}), 401
        
        # Check if token is blacklisted
        blacklist = get_token_blacklist()
        if blacklist.is_blacklisted(token):
            return jsonify({"error": "Token has been revoked"}), 401
        
        # Verify token
        payload = JWTManager.verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        # Add user info to request context
        request.user_id = payload['user_id']
        request.username = payload['username']
        request.email = payload['email']
        request.token_fingerprint = JWTManager.get_token_fingerprint(token)
        
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    """Get current user from token without failing"""
    token = None
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    
    if token:
        # Check blacklist first
        blacklist = get_token_blacklist()
        if not blacklist.is_blacklisted(token):
            payload = JWTManager.verify_token(token)
            if payload:
                return payload
    return None

def admin_required(f):
    """Require admin privileges"""
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        # You can implement admin check based on your user model
        # For now, this is a placeholder
        if not hasattr(request, 'username'):
            return jsonify({"error": "Authentication required"}), 401
            
        # Add your admin validation logic here
        # Example: if request.username not in ADMIN_USERS:
        #     return jsonify({"error": "Admin access required"}), 403
            
        return f(*args, **kwargs)
    return decorated