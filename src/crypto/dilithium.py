# src/crypto/dilithium.py
from dilithium_py.dilithium import Dilithium2

class DilithiumManager:
    @staticmethod
    def keygen():
        """Generate Dilithium DSA keypair"""
        return Dilithium2.keygen()
    
    @staticmethod
    def sign(message: bytes, private_key: bytes):
        """Sign a message using Dilithium private key"""
        return Dilithium2.sign(private_key, message)
    
    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes):
        """Verify a Dilithium signature"""
        return Dilithium2.verify(public_key, message, signature)