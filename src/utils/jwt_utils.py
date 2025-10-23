# src/utils/jwt_utils.py
import jwt
import secrets
import string
from datetime import datetime, timedelta
from flask import current_app
from typing import Dict, Any, Optional, Tuple
import base64
import json

class JWTManager:
    @staticmethod
    def _generate_random_token_id(length=32):
        """Generate a random token ID for jti claim"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def _generate_random_payload_salt(length=16):
        """Generate random salt to make payload unpredictable"""
        return secrets.token_urlsafe(length)

    @staticmethod
    def _obfuscate_payload(payload: Dict[str, Any], salt: str) -> Dict[str, Any]:
        """Add random data to make payload structure less predictable"""
        obfuscated = payload.copy()
        
        # Add random fields that will be ignored by our system but make tokens look different
        random_fields = {
            'rnd': secrets.token_urlsafe(8),
            'v': '1.0',  # version field
            'ct': datetime.utcnow().isoformat(),  # creation time
            'salt': salt
        }
        
        obfuscated.update(random_fields)
        return obfuscated

    @staticmethod
    def _clean_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Remove obfuscation fields before processing"""
        clean_payload = payload.copy()
        
        # Remove obfuscation fields (but keep private_keys if present)
        fields_to_remove = ['rnd', 'v', 'ct', 'salt', 'jti', 'iss', 'aud']
        for field in fields_to_remove:
            clean_payload.pop(field, None)
            
        return clean_payload

    @staticmethod
    def generate_access_token(user_id: str, username: str, email: str, private_keys: dict = None) -> str:
        """
        Generate random-looking JWT access token with optional private keys
        
        Args:
            user_id: User identifier
            username: Username
            email: User email
            private_keys: Optional dict with 'kem_private' and 'sig_private' keys (base64 encoded)
        
        Returns:
            JWT access token string
        """
        # Core claims
        payload = {
            'user_id': user_id,
            'username': username,
            'email': email,
            'type': 'access',
            'exp': datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
            'iat': datetime.utcnow(),
            'iss': 'quantum-chat-app',  # Issuer
            'aud': 'quantum-chat-client',  # Audience
            'jti': JWTManager._generate_random_token_id(),  # Unique token ID
        }

        # Add private keys if provided
        if private_keys:
            payload['private_keys'] = private_keys
            print(f"DEBUG: Access token generated with private keys for {username}")
        else:
            print(f"DEBUG: Access token generated WITHOUT private keys for {username}")

        # Add obfuscation
        salt = JWTManager._generate_random_payload_salt()
        obfuscated_payload = JWTManager._obfuscate_payload(payload, salt)

        # Generate token with random header parameters
        headers = {
            'typ': 'JWT',
            'alg': current_app.config['JWT_ALGORITHM'],
            'kid': secrets.token_urlsafe(8),  # Random key ID
            'cty': 'app-specific',  # Content type
        }

        return jwt.encode(
            obfuscated_payload, 
            current_app.config['JWT_SECRET_KEY'], 
            algorithm=current_app.config['JWT_ALGORITHM'],
            headers=headers
        )

    @staticmethod
    def generate_refresh_token(user_id: str) -> str:
        """Generate random-looking JWT refresh token (no private keys for security)"""
        payload = {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + current_app.config['JWT_REFRESH_TOKEN_EXPIRES'],
            'iat': datetime.utcnow(),
            'iss': 'quantum-chat-app',
            'aud': 'quantum-chat-client',
            'jti': JWTManager._generate_random_token_id(),
        }

        salt = JWTManager._generate_random_payload_salt()
        obfuscated_payload = JWTManager._obfuscate_payload(payload, salt)

        headers = {
            'typ': 'JWT',
            'alg': current_app.config['JWT_ALGORITHM'],
            'kid': secrets.token_urlsafe(8),
            'cty': 'app-specific',
        }

        return jwt.encode(
            obfuscated_payload, 
            current_app.config['JWT_SECRET_KEY'], 
            algorithm=current_app.config['JWT_ALGORITHM'],
            headers=headers
        )

    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return cleaned payload if valid"""
        try:
            payload = jwt.decode(
                token, 
                current_app.config['JWT_SECRET_KEY'], 
                algorithms=[current_app.config['JWT_ALGORITHM']],
                audience='quantum-chat-client',
                issuer='quantum-chat-app'
            )
            
            # Clean the payload before returning (keeps private_keys if present)
            return JWTManager._clean_payload(payload)
            
        except jwt.ExpiredSignatureError:
            print("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f"Invalid token: {e}")
            return None

    @staticmethod
    def refresh_access_token(refresh_token: str) -> Optional[str]:
        """
        Generate new access token using refresh token
        Note: New token will NOT have private keys (user needs to login for that)
        """
        payload = JWTManager.verify_token(refresh_token)
        if not payload or payload.get('type') != 'refresh':
            return None
        
        # Get user details from database
        from src.models.user import UserManager
        users_file = current_app.config.get('USERS_FILE', 'data/users.json')
        user_manager = UserManager(users_file)
        user = user_manager.get_user(payload['user_id'])
        
        if not user:
            return None
        
        # Generate new access token WITHOUT private keys
        # User must login again for private keys
        return JWTManager.generate_access_token(
            user.id, 
            user.username, 
            user.email,
            private_keys=None  # No private keys on refresh
        )

    @staticmethod
    def generate_api_key(user_id: str, username: str, permissions: list = None) -> str:
        """Generate random-looking API key (extended lifetime token, no private keys)"""
        if permissions is None:
            permissions = ['read', 'write']
            
        payload = {
            'user_id': user_id,
            'username': username,
            'type': 'api_key',
            'permissions': permissions,
            'exp': datetime.utcnow() + timedelta(days=365),  # 1 year for API keys
            'iat': datetime.utcnow(),
            'iss': 'quantum-chat-app',
            'aud': 'quantum-chat-api',
            'jti': JWTManager._generate_random_token_id(64),  # Longer ID for API keys
        }

        salt = JWTManager._generate_random_payload_salt(32)
        obfuscated_payload = JWTManager._obfuscate_payload(payload, salt)

        # Different headers for API keys
        headers = {
            'typ': 'JWT',
            'alg': current_app.config['JWT_ALGORITHM'],
            'kid': secrets.token_urlsafe(16),  # Longer key ID
            'cty': 'api-key',
        }

        return jwt.encode(
            obfuscated_payload, 
            current_app.config['JWT_SECRET_KEY'], 
            algorithm=current_app.config['JWT_ALGORITHM'],
            headers=headers
        )

    @staticmethod
    def generate_short_lived_token(user_id: str, username: str, purpose: str, expires_in_minutes: int = 5) -> str:
        """Generate short-lived token for specific operations"""
        payload = {
            'user_id': user_id,
            'username': username,
            'type': 'short_lived',
            'purpose': purpose,
            'exp': datetime.utcnow() + timedelta(minutes=expires_in_minutes),
            'iat': datetime.utcnow(),
            'iss': 'quantum-chat-app',
            'aud': f'quantum-chat-{purpose}',
            'jti': JWTManager._generate_random_token_id(),
        }

        salt = JWTManager._generate_random_payload_salt()
        obfuscated_payload = JWTManager._obfuscate_payload(payload, salt)

        headers = {
            'typ': 'JWT',
            'alg': current_app.config['JWT_ALGORITHM'],
            'kid': secrets.token_urlsafe(8),
            'cty': f'short-{purpose}',
        }

        return jwt.encode(
            obfuscated_payload, 
            current_app.config['JWT_SECRET_KEY'], 
            algorithm=current_app.config['JWT_ALGORITHM'],
            headers=headers
        )

    @staticmethod
    def decode_token_without_verification(token: str) -> Optional[Dict[str, Any]]:
        """Decode token without verification (for inspection only)"""
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            print(f"Token decode error: {e}")
            return None

    @staticmethod
    def get_token_fingerprint(token: str) -> str:
        """Generate a fingerprint for token tracking"""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()[:16]
    
    @staticmethod
    def extract_private_keys(token: str) -> Optional[Dict[str, str]]:
        """
        Extract private keys from token (if present)
        
        Args:
            token: JWT token string
        
        Returns:
            Dict with private keys or None
        """
        payload = JWTManager.verify_token(token)
        if payload:
            return payload.get('private_keys')
        return None
    
    @staticmethod
    def has_private_keys(token: str) -> bool:
        """
        Check if token contains private keys
        
        Args:
            token: JWT token string
        
        Returns:
            True if token has private keys, False otherwise
        """
        payload = JWTManager.verify_token(token)
        if payload:
            return 'private_keys' in payload
        return False