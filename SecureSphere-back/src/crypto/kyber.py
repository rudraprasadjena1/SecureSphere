# src/crypto/kyber.py
from kyber_py.kyber import Kyber512

class KyberManager:
    @staticmethod
    def keygen():
        """Generate Kyber KEM keypair"""
        return Kyber512.keygen()
    
    @staticmethod
    def encrypt(plaintext: bytes, public_key: bytes):
        """Encapsulate to generate shared secret and ciphertext"""
        shared_key, ciphertext = Kyber512.encaps(public_key)
        return shared_key, ciphertext
    
    @staticmethod
    def decrypt(ciphertext: bytes, private_key: bytes):
        """Decapsulate to recover shared secret"""
        shared_key = Kyber512.decaps(private_key, ciphertext)
        return shared_key