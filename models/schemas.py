from pydantic import BaseModel
from typing import Optional


class User(BaseModel):
    username: str
    password: str
    is_admin: bool
    access_token: Optional[str] = None
