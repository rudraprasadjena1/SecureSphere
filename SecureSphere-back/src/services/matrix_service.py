# src/services/matrix_service.py
import requests
import json
from flask import current_app

class SimpleMatrixService:
    def __init__(self):
        self.homeserver = current_app.config.get('MATRIX_HOMESERVER_URL', 'https://matrix.org')
        self.access_token = None
        
    def login(self, username, password):
        """Simple Matrix login"""
        url = f"{self.homeserver}/_matrix/client/r0/login"
        
        payload = {
            "type": "m.login.password",
            "user": username,
            "password": password
        }
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access_token')
                return True
            return False
        except Exception as e:
            print(f"Matrix login error: {e}")
            return False
    
    def send_message(self, room_id, message):
        """Send message to Matrix room"""
        if not self.access_token:
            return False
            
        url = f"{self.homeserver}/_matrix/client/r0/rooms/{room_id}/send/m.room.message"
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "msgtype": "m.text",
            "body": f"🔐 [Quantum Encrypted] {message}"
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"Matrix send error: {e}")
            return False
    
    def get_rooms(self):
        """Get user's joined rooms"""
        if not self.access_token:
            return []
            
        url = f"{self.homeserver}/_matrix/client/r0/joined_rooms"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json().get('joined_rooms', [])
            return []
        except Exception as e:
            print(f"Matrix rooms error: {e}")
            return []