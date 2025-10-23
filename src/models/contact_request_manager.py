# src\models\contact_request_manager.py
import json
import os
from datetime import datetime
from uuid import uuid4

class ContactRequestManager:
    def __init__(self, requests_file="data/contact_requests.json"):
        self.requests_file = requests_file
        self._ensure_file()
        self.requests = self._load_requests()

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.requests_file), exist_ok=True)
        if not os.path.exists(self.requests_file):
            with open(self.requests_file, 'w') as f:
                json.dump({}, f)

    def _load_requests(self):
        try:
            with open(self.requests_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save_requests(self):
        with open(self.requests_file, 'w') as f:
            json.dump(self.requests, f, indent=2)

    def create_request(self, from_user_id, to_user_id, message=""):
        # Check if a request already exists
        existing = self.get_request_between_users(from_user_id, to_user_id)
        if existing:
            return None # Request already exists

        request_id = str(uuid4())
        now = datetime.now().isoformat()
        
        new_request = {
            "id": request_id,
            "from_user_id": from_user_id,
            "to_user_id": to_user_id,
            "status": "pending",
            "message": message,
            "created_at": now,
            "updated_at": now,
        }
        self.requests[request_id] = new_request
        self._save_requests()
        return new_request

    def get_request(self, request_id):
        return self.requests.get(request_id)

    def get_request_between_users(self, user1, user2):
        for req in self.requests.values():
            participants = {req['from_user_id'], req['to_user_id']}
            if participants == {user1, user2}:
                return req
        return None

    def update_request_status(self, request_id, status):
        if request_id in self.requests:
            self.requests[request_id]['status'] = status
            self.requests[request_id]['updated_at'] = datetime.now().isoformat()
            self._save_requests()
            return self.requests[request_id]
        return None
    
    def get_pending_requests_for_user(self, user_id):
        pending = []
        for req in self.requests.values():
            if (req['to_user_id'] == user_id or req['from_user_id'] == user_id) and req['status'] == 'pending':
                pending.append(req)
        return pending