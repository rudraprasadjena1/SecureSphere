# src/models/user.py
import json
import os
from datetime import datetime
from hashlib import sha256
from typing import Optional, List # Import required types
from src.crypto.key_protection import KeyProtection
from ..models.schemas import User # Your Pydantic User model

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
        """Hash password (use bcrypt in production)"""
        return sha256(password.encode()).hexdigest()

    # --- MODIFIED: create_user ---
    # Now returns a Pydantic User model
    def create_user(self, username: str, email: str, password: str, kem_public_key: str,
                sig_public_key: str, kem_private_key: bytes,
                sig_private_key: bytes) -> Optional[User]:
        """Create user and return a Pydantic User model."""
        if username in self.users:
            print(f"User {username} already exists.")
            return None

        encrypted_kem_private = KeyProtection.encrypt_private_key(kem_private_key, password)
        encrypted_sig_private = KeyProtection.encrypt_private_key(sig_private_key, password)

        # The dictionary we store on disk includes sensitive data
        # and aligns with our storage format.
        user_data_to_store = {
            "id": username,  # Use username as the user ID
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
        
        # Return a clean, validated Pydantic model.
        # Pydantic will automatically ignore extra fields like 'password_hash'.
        return User.parse_obj(user_data_to_store)

    # --- MODIFIED: get_user ---
    # Now returns an Optional[User] Pydantic model
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username and return a Pydantic model."""
        user_data = self.users.get(username)
        if user_data:
            # Convert the stored dictionary into a Pydantic User object.
            # This ensures the data is in the expected format and validated.
            return User.parse_obj(user_data)
        return None

    def get_user_internal(self, username: str) -> Optional[dict]:
        """Get the full user dictionary, including private data."""
        return self.users.get(username)

    def verify_password(self, username: str, password: str) -> bool:
        """Verify user password"""
        user = self.get_user_internal(username) # Use internal method
        if not user:
            return False
        return user["password_hash"] == self.hash_password(password)

    # --- MODIFIED: get_all_users ---
    # Now returns a List[User] of Pydantic models
    def get_all_users(self) -> List[User]:
        """Get all users as a list of Pydantic User models."""
        users_list = []
        for user_data in self.users.values():
            # Parse each user dictionary into a User model. This strips out
            # sensitive data and ensures consistent structure.
            users_list.append(User.parse_obj(user_data))
        return users_list

    # --- Other methods remain largely the same, but should use get_user_internal ---
    # --- for operations that modify the stored dictionary ---

    def update_login_status(self, username: str, is_online: bool):
        """Update user online status"""
        user = self.get_user_internal(username) # Use internal method
        if user:
            user["is_online"] = is_online
            if is_online:
                user["last_seen"] = datetime.now().isoformat()
            else:
                user["last_seen"] = datetime.now().isoformat() # Also update on logout
            self.save_users()
            
    def get_private_key(self, username: str, password: str, key_type: str):
        """Retrieve and decrypt private key"""
        user = self.get_user_internal(username) # Use internal method
        if not user or not self.verify_password(username, password):
            return None

        encrypted_key_field = f"encrypted_{key_type}_private"
        if encrypted_key_field not in user:
            return None
        
        encrypted_key_data = user[encrypted_key_field]
        
        try:
            # ... (rest of the decryption logic remains the same) ...
            return KeyProtection.decrypt_private_key(encrypted_key_data, password)
        except Exception as e:
            print(f"Failed to decrypt private key for {username}: {e}")
            return None

    def clear_users(self):
        """Clear all users (for testing)"""
        self.users = {}
        self.save_users()