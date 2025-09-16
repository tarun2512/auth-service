from pydantic import BaseModel, EmailStr
from typing import Optional

class OrganizerRegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    company_name: str
    license_number: Optional[str] = None
    gst_number: Optional[str] = None
    contact_number: Optional[str] = None
    address: Optional[str] = None
    bank_account_number: Optional[str] = None
    bank_ifsc_code: Optional[str] = None


class OrganizerLoginRequest(BaseModel):
    email: EmailStr
    password: str


class OrganizerResponse(BaseModel):
    user_id: str
    email: str
    full_name: Optional[str]
    user_type: str
    company_name: str
