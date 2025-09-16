from typing import Any, Optional

from pydantic import BaseModel


class DefaultResponse(BaseModel):
    status: str = "Failed"
    message: Optional[str] = ""
    data: Optional[Any] = None


class DefaultFailureResponse(DefaultResponse):
    error: Any = None
    message: Optional[Any] = None
    status: Optional[str] = "Failed"


class DefaultSuccessResponse(BaseModel):
    status: str = "success"
    message: Optional[str] = ""
    data: Any = None


class GetTokenResponse(BaseModel):
    status: str
    verify_signature: bool
    unique_key: str
    c_key: Optional[str] = None