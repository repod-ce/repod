from pydantic import BaseModel
from typing import Optional


class Token(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    # Champs MFA (présents uniquement si mfa_required=True)
    mfa_required: Optional[bool] = None
    mfa_token: Optional[str] = None


class MfaSetupResponse(BaseModel):
    secret: str
    uri: str
    qr_code_base64: str


class MfaConfirmRequest(BaseModel):
    totp_code: str


class MfaAuthenticateRequest(BaseModel):
    mfa_token: str
    totp_code: str


class MfaDisableRequest(BaseModel):
    password: str


class TokenData(BaseModel):
    username: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "reader"
    full_name: str = ""
    email: str = ""


class UserUpdate(BaseModel):
    role: Optional[str] = None
    full_name: Optional[str] = None
    email: Optional[str] = None
    active: Optional[bool] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class PasswordReset(BaseModel):
    new_password: str


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    full_name: str
    email: str
    active: bool
    created_at: str
    last_login: Optional[str] = None
