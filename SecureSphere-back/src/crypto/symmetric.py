# src/crypto/symmetric.py
from Crypto.Cipher import AES

class SymmetricManager:
    @staticmethod
    def encrypt(message: bytes, key: bytes):
        """Encrypt message with AES-GCM"""
        cipher = AES.new(key[:32], AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        return cipher.nonce, ciphertext, tag
    
    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):
        """Decrypt and verify AES-GCM ciphertext"""
        cipher = AES.new(key[:32], AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)