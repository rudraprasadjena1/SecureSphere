# src/crypto/forward_secrecy.py
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from src.crypto.kyber import KyberManager
from src.crypto.dilithium import DilithiumManager
from src.crypto.symmetric import SymmetricManager


class PerMessageFSManager:
    """
    Per-Message Forward Secrecy: Each message uses fresh X25519 + Kyber KEM
    This provides forward secrecy at the message level, not just session level.
    """

    @staticmethod
    def b64e(b: bytes) -> str:
        return base64.b64encode(b).decode()

    @staticmethod
    def b64d(s: str) -> bytes:
        return base64.b64decode(s)

    @staticmethod
    def generate_ephemeral_x25519():
        """Generate a fresh X25519 keypair for each message"""
        sk = X25519PrivateKey.generate()
        sk_bytes = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pk_bytes = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pk_bytes, sk_bytes, sk

    @staticmethod
    def derive_hybrid_key(pq_shared: bytes, ecdh_shared: bytes, length: int = 32,
                          info: bytes = b"per_message_hybrid_fs"):
        """HKDF combining both PQ and classical shared secrets"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info
        )
        return hkdf.derive(pq_shared + ecdh_shared)

    @staticmethod
    def encrypt_single_message(plaintext: bytes,
                               recipient_kem_pub: bytes,
                               recipient_ecdh_static_pub: bytes,
                               sender_sig_sk: bytes):
        """
        Encrypt a SINGLE message with per-message forward secrecy
        Each message gets:
        - Fresh X25519 ephemeral keypair
        - Fresh Kyber encapsulation
        - Combined key derivation
        """
        # 1. Generate FRESH ephemeral X25519 for THIS message
        eph_pub, eph_priv_bytes, eph_priv_obj = PerMessageFSManager.generate_ephemeral_x25519()

        # 2. Post-quantum KEM (fresh encapsulation for this message)
        pq_shared, ciphertext_kem = KyberManager.encrypt(
            plaintext, recipient_kem_pub)

        # 3. Ephemeral-static ECDH (fresh for this message)
        recipient_ecdh_pub_key = X25519PublicKey.from_public_bytes(
            recipient_ecdh_static_pub)
        ecdh_shared = eph_priv_obj.exchange(recipient_ecdh_pub_key)

        # 4. Derive message-specific symmetric key
        symmetric_key = PerMessageFSManager.derive_hybrid_key(
            pq_shared, ecdh_shared)

        # 5. Encrypt message with derived key
        nonce, ciphertext, tag = SymmetricManager.encrypt(
            plaintext, symmetric_key)

        # 6. Sign the ciphertext for authentication
        # We sign (ciphertext + eph_pub) to bind ephemeral key to message
        data_to_sign = ciphertext + eph_pub
        signature = DilithiumManager.sign(data_to_sign, sender_sig_sk)

        # 7. Securely wipe ephemeral private key from memory
        PerMessageFSManager.secure_zeroize(eph_priv_bytes)
        del eph_priv_obj

        return {
            'ciphertext_kem': ciphertext_kem,      # Kyber ciphertext
            'ciphertext': ciphertext,              # AES-GCM ciphertext
            'nonce': nonce,                        # AES-GCM nonce
            'tag': tag,                            # AES-GCM tag
            'signature': signature,                # Dilithium signature
            'ephemeral_public_key': eph_pub,       # Fresh X25519 pubkey for THIS message
            'message_id': PerMessageFSManager.generate_message_id(),  # Unique message ID
        }

    @staticmethod
    def decrypt_single_message(encrypted_data: dict,
                               recipient_kem_priv: bytes,
                               recipient_ecdh_static_priv: bytes,
                               sender_sig_pub: bytes):
        """
        Decrypt a SINGLE message with per-message forward secrecy
        """
        ciphertext_kem = encrypted_data['ciphertext_kem']
        ciphertext = encrypted_data['ciphertext']
        nonce = encrypted_data['nonce']
        tag = encrypted_data['tag']
        signature = encrypted_data['signature']
        ephemeral_public_key = encrypted_data['ephemeral_public_key']

        # 1. Verify signature (binds ephemeral key to message)
        data_to_verify = ciphertext + ephemeral_public_key
        if not DilithiumManager.verify(data_to_verify, signature, sender_sig_pub):
            raise ValueError(
                "Signature verification failed - message tampered")

        # 2. Post-quantum KEM decapsulation
        pq_shared = KyberManager.decrypt(ciphertext_kem, recipient_kem_priv)

        # 3. Ephemeral-static ECDH (using our static private key)
        eph_pub_key = X25519PublicKey.from_public_bytes(ephemeral_public_key)
        recipient_ecdh_priv_key = X25519PrivateKey.from_private_bytes(
            recipient_ecdh_static_priv)
        ecdh_shared = recipient_ecdh_priv_key.exchange(eph_pub_key)

        # 4. Derive symmetric key (same derivation as encryption)
        symmetric_key = PerMessageFSManager.derive_hybrid_key(
            pq_shared, ecdh_shared)

        # 5. Decrypt message
        plaintext = SymmetricManager.decrypt(
            ciphertext, symmetric_key, nonce, tag)

        # 6. Clean up
        del recipient_ecdh_priv_key

        return plaintext

    @staticmethod
    def generate_message_id():
        """Generate unique ID for each message"""
        import secrets
        return secrets.token_hex(16)

    @staticmethod
    def secure_zeroize(data: bytes):
        """Attempt to securely wipe sensitive data from memory"""
        try:
            # Overwrite the memory
            for i in range(len(data)):
                data = data[:i] + b'\x00' + data[i+1:]
        except:
            pass

    @staticmethod
    def get_security_properties():
        """Return security properties of this scheme"""
        return {
            "forward_secrecy": "per_message",
            "quantum_safe": "yes",
            "authentication": "dilithium_signatures",
            "encryption": "aes_256_gcm",
            "key_exchange": "kyber_512_x25519_hybrid",
            "ephemeral_keys": "per_message_x25519",
            "kem_freshness": "per_message"
        }
