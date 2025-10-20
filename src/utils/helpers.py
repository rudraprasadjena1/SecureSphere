# src/utils/helpers.py
import base64

def b64encode(data: bytes) -> str:
    """Encode bytes to base64 string"""
    return base64.b64encode(data).decode()

def b64decode(data: str) -> bytes:
    """Decode base64 string to bytes"""
    return base64.b64decode(data)

def validate_username(username: str) -> bool:
    """Validate username format"""
    if not username or len(username) < 3:
        return False
    # Add more validation as needed
    return True