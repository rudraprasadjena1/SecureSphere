from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

class User(BaseModel):
    id: str
    username: str
    email: str
    kem_public_key: str
    sig_public_key: str
    is_online: bool = False
    last_seen: Optional[datetime] = None
    created_at: datetime
    contacts: List[str] = []  # List of user IDs

    class Config:
        orm_mode = True # Helps Pydantic work with data from other sources
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class ContactRequest(BaseModel):
    id: str
    from_user_id: str
    to_user_id: str
    status: str  # 'pending', 'accepted', 'rejected'
    message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class ContactResponse(BaseModel):
    id: str
    username: str
    email: str
    kem_public_key: str
    sig_public_key: str
    is_online: bool
    last_seen: Optional[datetime]
    status: str


class ForwardSecretMessage(BaseModel):
    """Schema for per-message forward secret messages"""
    message_id: str
    sender: str
    recipient: str
    ciphertext_kem: str  # base64
    ciphertext: str      # base64  
    nonce: str          # base64
    tag: str            # base64
    signature: str      # base64
    ephemeral_public_key: str  # base64 - FRESH for each message
    timestamp: datetime
    version: str = "2.0-per-message-fs"
    algorithm: str = "Kyber512-X25519-Per-Message-FS"
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }