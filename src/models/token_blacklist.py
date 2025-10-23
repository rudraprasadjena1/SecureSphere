# src/models/token_blacklist.py
import json
import os
from datetime import datetime, timedelta

class TokenBlacklist:
    def __init__(self, blacklist_file="data/token_blacklist.json"):
        self.blacklist_file = blacklist_file
        self._ensure_file()
        self.blacklist = self._load_blacklist()

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.blacklist_file), exist_ok=True)
        if not os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, 'w') as f:
                json.dump({}, f)

    def _load_blacklist(self):
        try:
            with open(self.blacklist_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save_blacklist(self):
        with open(self.blacklist_file, 'w') as f:
            json.dump(self.blacklist, f, indent=2)

    def add_token(self, token: str, user_id: str, expires_at: str, reason: str = "logout"):
        """Add token to blacklist"""
        token_fingerprint = self._get_token_fingerprint(token)
        
        self.blacklist[token_fingerprint] = {
            'user_id': user_id,
            'expires_at': expires_at,
            'blacklisted_at': datetime.now().isoformat(),
            'reason': reason
        }
        self._save_blacklist()

    def is_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        token_fingerprint = self._get_token_fingerprint(token)
        return token_fingerprint in self.blacklist

    def _get_token_fingerprint(self, token: str) -> str:
        """Generate fingerprint for token"""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()

    def cleanup_expired(self):
        """Remove expired tokens from blacklist"""
        now = datetime.now()
        initial_count = len(self.blacklist)
        
        self.blacklist = {
            fp: data for fp, data in self.blacklist.items() 
            if datetime.fromisoformat(data['expires_at']) > now
        }
        
        if len(self.blacklist) != initial_count:
            self._save_blacklist()
            print(f"Cleaned up {initial_count - len(self.blacklist)} expired tokens")

    def get_user_blacklisted_tokens(self, user_id: str):
        """Get all blacklisted tokens for a user"""
        return {
            fp: data for fp, data in self.blacklist.items() 
            if data['user_id'] == user_id
        }