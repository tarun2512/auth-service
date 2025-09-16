from pydantic import BaseModel, EmailStr
from typing import Optional

class TravellerRegister(BaseModel):
    user_id: Optional[str] = ""
    traveller_id: Optional[str] = ""
    user_type: str
    email: EmailStr
    password: str
    full_name: str
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    contact_number: Optional[str] = None
    address: Optional[str] = None

class TravellerLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    user_id: str
    email: EmailStr
    full_name: Optional[str]

    class Config:
        from_attributes = True
