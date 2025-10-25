# src/models/message.py
import json
import os
from datetime import datetime
from src.utils.helpers import b64encode, b64decode

class MessageManager:
    def __init__(self, messages_file='data/messages.json'):
        self.messages_file = messages_file
        self._ensure_messages_file()
    
    def _ensure_messages_file(self):
        """Create messages file if it doesn't exist"""
        os.makedirs(os.path.dirname(self.messages_file), exist_ok=True)
        if not os.path.exists(self.messages_file):
            with open(self.messages_file, 'w') as f:
                json.dump({}, f)
    
    def _load_messages(self):
        """Load all messages from file"""
        try:
            with open(self.messages_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _save_messages(self, messages):
        """Save messages to file"""
        with open(self.messages_file, 'w') as f:
            json.dump(messages, f, indent=2)
    
    def store_message(self, sender, recipient, message_data):
        """Store an encrypted message"""
        messages = self._load_messages()
        
        # Create conversation key (sorted to ensure consistent ordering)
        participants = sorted([sender, recipient])
        conversation_id = f"{participants[0]}_{participants[1]}"
        
        if conversation_id not in messages:
            messages[conversation_id] = []
        
        # Add timestamp if not present
        if 'timestamp' not in message_data:
            message_data['timestamp'] = datetime.now().isoformat()
        
        messages[conversation_id].append(message_data)
        self._save_messages(messages)
        
        return conversation_id
    
    def get_conversation_history(self, user1, user2):
        """Get message history between two users"""
        messages = self._load_messages()
        
        # Try both possible conversation IDs
        participants1 = sorted([user1, user2])
        conversation_id = f"{participants1[0]}_{participants1[1]}"
        
        if conversation_id in messages:
            return messages[conversation_id]
        return []
    
    def get_user_conversations(self, username):
        """Get all conversations for a user"""
        messages = self._load_messages()
        conversations = []
        
        for conversation_id, message_list in messages.items():
            users = conversation_id.split('_')
            if username in users:
                # Get the other user in the conversation
                other_user = users[0] if users[1] == username else users[1]
                
                # Get the last message for preview
                last_message = message_list[-1] if message_list else None
                
                conversations.append({
                    'other_user': other_user,
                    'conversation_id': conversation_id,
                    'last_message': last_message,
                    'message_count': len(message_list),
                    'last_updated': last_message['timestamp'] if last_message else None
                })
        
        # Sort by last updated timestamp (newest first)
        conversations.sort(key=lambda x: x['last_updated'] or '', reverse=True)
        return conversations