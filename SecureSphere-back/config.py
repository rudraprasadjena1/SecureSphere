# config.py - Enhanced JWT configuration
import os
from datetime import timedelta

class Config:
    MESSAGES_FILE = 'data/messages.json'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'quantum-safe-secret-key-change-in-production'
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    USERS_FILE = os.environ.get('USERS_FILE') or 'data/users.json'
    
    # Enhanced JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ALGORITHM = 'HS256'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_ISSUER = 'quantum-chat-app'
    JWT_AUDIENCE = 'quantum-chat-client'
    
    # Token security settings
    JWT_TOKEN_PREFIX = 'qc_'  # Prefix for all tokens
    JWT_MAX_TOKENS_PER_USER = 5  # Maximum concurrent tokens per user
    
    # Cryptographic settings
    KEM_ALGORITHM = 'Kyber512'
    SIG_ALGORITHM = 'Dilithium2'
    SYMMETRIC_ALGORITHM = 'AES-GCM'
    
    MATRIX_HOMESERVER_URL = os.environ.get('MATRIX_HOMESERVER_URL', 'https://matrix.org')
    MATRIX_INTEGRATION_ENABLED = True