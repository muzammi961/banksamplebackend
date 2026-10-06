from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):

    email: EmailStr

    password: str = Field(
        min_length=6,
        max_length=128,
    )


class LoginRequest(BaseModel):

    email: EmailStr

    password: str


class TokenResponse(BaseModel):

    access_token: str

    token_type: str

    expires_in: int

    user_id: str

    biometric_enabled: bool


class UserResponse(BaseModel):

    id: str

    email: str

    is_active: bool

    biometric_enabled: bool


class BiometricEnableResponse(BaseModel):

    message: str

    biometric_enabled: bool