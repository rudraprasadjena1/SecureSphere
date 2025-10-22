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