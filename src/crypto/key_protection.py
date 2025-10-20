# src/crypto/key_protection.py
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from src.utils.helpers import b64encode, b64decode

class KeyProtection:
    @staticmethod
    def encrypt_private_key(private_key: bytes, password: str) -> dict:
        """Encrypt private key with user's password using AES-GCM"""
        salt = get_random_bytes(32)
        # Derive key from password
        key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
        
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(private_key)
        
        return {
            'ciphertext': b64encode(ciphertext),
            'salt': b64encode(salt),
            'nonce': b64encode(cipher.nonce),
            'tag': b64encode(tag)
        }
    
    @staticmethod
    def decrypt_private_key(encrypted_data: dict, password: str) -> bytes:
        """Decrypt private key with user's password"""
        ciphertext = b64decode(encrypted_data['ciphertext'])
        salt = b64decode(encrypted_data['salt'])
        nonce = b64decode(encrypted_data['nonce'])
        tag = b64decode(encrypted_data['tag'])
        
        # Derive the same key
        key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)