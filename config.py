# config.py - Application configuration
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'quantum-safe-secret-key'
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    USERS_FILE = os.environ.get('USERS_FILE') or 'data/users.json'
    
    # Cryptographic settings
    KEM_ALGORITHM = 'Kyber512'
    SIG_ALGORITHM = 'Dilithium2'
    SYMMETRIC_ALGORITHM = 'AES-GCM'