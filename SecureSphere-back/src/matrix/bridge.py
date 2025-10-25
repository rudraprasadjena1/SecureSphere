# src/matrix/bridge.py
import asyncio
import json
import aiohttp
from flask import current_app
from src.models.user import UserManager
from src.models.message import MessageManager
from src.utils.jwt_utils import JWTManager

class MatrixBridge:
    def __init__(self, homeserver_url, access_token):
        self.homeserver_url = homeserver_url
        self.access_token = access_token
        self.session = None
        
    async def start(self):
        self.session = aiohttp.ClientSession()
        
    async def stop(self):
        if self.session:
            await self.session.close()
    
    async def create_user(self, matrix_user_id, display_name=None):
        """Create a virtual user in Matrix"""
        url = f"{self.homeserver_url}/_matrix/client/r0/register"
        
        payload = {
            "type": "m.login.application_service",
            "username": matrix_user_id.replace("@", "").replace(":", ""),
        }
        
        if display_name:
            payload["displayname"] = display_name
            
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        async with self.session.post(url, json=payload, headers=headers) as resp:
            if resp.status == 200:
                return await resp.json()
            return None
    
    async def join_room(self, user_id, room_id_or_alias):
        """Make a user join a room"""
        url = f"{self.homeserver_url}/_matrix/client/r0/join/{room_id_or_alias}"
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        async with self.session.post(url, headers=headers) as resp:
            return resp.status == 200
    
    async def send_message(self, room_id, message_content, msgtype="m.text"):
        """Send a message to a Matrix room"""
        url = f"{self.homeserver_url}/_matrix/client/r0/rooms/{room_id}/send/m.room.message"
        
        payload = {
            "msgtype": msgtype,
            "body": message_content
        }
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        async with self.session.post(url, json=payload, headers=headers) as resp:
            return resp.status == 200