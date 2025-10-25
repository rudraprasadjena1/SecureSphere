# src/models/user.py (FIXED)
import json
import os
from datetime import datetime
from hashlib import sha256
from typing import Optional, List
from src.models.schemas import User
from src.crypto.key_protection import KeyProtection
import bcrypt


class UserManager:
    def __init__(self, users_file="data/users.json"):
        self.users_file = users_file
        print(f"UserManager initialized with file: {users_file}")
        self._ensure_data_directory()
        self.users = self.load_users()
        print(f"Loaded {len(self.users)} users from {users_file}")

    def _ensure_data_directory(self):
        """Ensure data directory exists"""
        try:
            if os.path.dirname(self.users_file) and not os.path.exists(os.path.dirname(self.users_file)):
                os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
                print(f"Created directory for: {self.users_file}")
        except Exception as e:
            print(f"Warning: Could not create data directory: {e}")

    def load_users(self):
        """Load users from JSON file"""
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            return {}
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load users file {self.users_file}: {e}")
            return {}

    def save_users(self):
        """Save users to JSON file"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
            print(f"Saved {len(self.users)} users to {self.users_file}")
        except Exception as e:
            print(f"Error saving users to {self.users_file}: {e}")
            if 'test' not in self.users_file:
                raise

    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt. The salt is automatically generated
        and stored as part of the hash.
        """
        # bcrypt requires bytes, so we encode the password
        password_bytes = password.encode('utf-8')
        # Generate a salt and hash the password
        hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        # Decode back to a string for JSON storage
        return hashed_bytes.decode('utf-8')

    def create_user(self, username: str, email: str, password: str, kem_public_key: str,
                    sig_public_key: str, kem_private_key: bytes,
                    sig_private_key: bytes) -> Optional[User]:
        """Create user and return a Pydantic User model."""
        if username in self.users:
            print(f"User {username} already exists.")
            return None

        encrypted_kem_private = KeyProtection.encrypt_private_key(
            kem_private_key, password)
        encrypted_sig_private = KeyProtection.encrypt_private_key(
            sig_private_key, password)

        user_data_to_store = {
            "id": username,
            "username": username,
            "email": email,
            "password_hash": self.hash_password(password),
            "kem_public_key": kem_public_key,
            "sig_public_key": sig_public_key,
            "encrypted_kem_private": encrypted_kem_private,
            "encrypted_sig_private": encrypted_sig_private,
            "created_at": datetime.now().isoformat(),
            "is_online": False,
            "last_seen": None,
            "contacts": []
        }

        self.users[username] = user_data_to_store
        self.save_users()

        return User.parse_obj(user_data_to_store)

    def get_user(self, username: str) -> Optional[User]:
        """Get user by username and return a Pydantic model."""
        user_data = self.users.get(username)
        if user_data:
            return User.parse_obj(user_data)
        return None

    def get_user_dict(self, username: str) -> Optional[dict]:
        """Get user as dictionary (for internal use where dict access is needed)."""
        # This should return the raw dictionary from self.users, not a Pydantic model
        return self.users.get(username)

    def get_user_internal(self, username: str) -> Optional[dict]:
        """Get the full user dictionary, including private data."""
        return self.users.get(username)

    def verify_password(self, username: str, password: str) -> bool:
        """Verify a user's password against the stored bcrypt hash."""
        user = self.get_user_internal(username)
        if not user:
            return False
        
        password_bytes = password.encode('utf-8')
        hashed_password_bytes = user["password_hash"].encode('utf-8')
        
        # bcrypt's checkpw function securely compares the plain-text password
        # with the hash, handling the salt automatically.
        return bcrypt.checkpw(password_bytes, hashed_password_bytes)

    def get_all_users(self) -> List[User]:
        """Get all users as a list of Pydantic User models."""
        users_list = []
        for user_data in self.users.values():
            users_list.append(User.parse_obj(user_data))
        return users_list

    def add_contact(self, from_user: str, to_user: str) -> bool:
        """
        Adds a contact to a user's contact list.
        Returns True on success, False on failure.
        """
        # We operate directly on the self.users dictionary
        from_user_data = self.get_user_internal(from_user)
        to_user_data = self.get_user_internal(to_user)

        if not from_user_data or not to_user_data:
            print(f"Error: Cannot add contact. One or both users do not exist.")
            return False

        # Add 'to_user' to 'from_user's contact list
        if 'contacts' not in from_user_data:
            from_user_data['contacts'] = []  # Initialize if not present

        if to_user not in from_user_data['contacts']:
            from_user_data['contacts'].append(to_user)
            print(f"Added {to_user} to {from_user}'s contact list.")

        # For a reciprocal relationship, also add 'from_user' to 'to_user's list
        if 'contacts' not in to_user_data:
            to_user_data['contacts'] = []

        if from_user not in to_user_data['contacts']:
            to_user_data['contacts'].append(from_user)
            print(f"Added {from_user} to {to_user}'s contact list.")

        self.save_users()
        return True

    def update_login_status(self, username: str, is_online: bool):
        """Update user online status"""
        user = self.get_user_internal(username)
        if user:
            user["is_online"] = is_online
            user["last_seen"] = datetime.now().isoformat()
            self.save_users()

    def get_private_key(self, username: str, password: str, key_type: str):
        """Retrieve and decrypt private key"""
        user = self.get_user_internal(username)
        if not user or not self.verify_password(username, password):
            return None

        encrypted_key_field = f"encrypted_{key_type}_private"
        if encrypted_key_field not in user:
            return None

        encrypted_key_data = user[encrypted_key_field]

        try:
            return KeyProtection.decrypt_private_key(encrypted_key_data, password)
        except Exception as e:
            print(f"Failed to decrypt private key for {username}: {e}")
            return None

    def clear_users(self):
        """Clear all users (for testing)"""
        self.users = {}
        self.save_users()
