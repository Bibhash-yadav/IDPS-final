
import re

from datetime import date, datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    computed_field,
    field_validator,
)

from app.utils.age import calculate_age


# =========================================================
# REGISTRATION
# =========================================================

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    date_of_birth: date

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()

        if len(value) < 2:
            raise ValueError(
                "Name must contain at least 2 characters"
            )

        return value

    @field_validator("date_of_birth")
    @classmethod
    def validate_date_of_birth(cls, value: date) -> date:
        today = date.today()

        if value > today:
            raise ValueError(
                "Date of birth cannot be in the future"
            )

        age = calculate_age(value)

        if age is not None and age > 120:
            raise ValueError(
                "Please enter a valid date of birth"
            )

        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not re.search(r"[A-Z]", value):
            raise ValueError(
                "Password needs an uppercase letter"
            )

        if not re.search(r"[a-z]", value):
            raise ValueError(
                "Password needs a lowercase letter"
            )

        if not re.search(r"\d", value):
            raise ValueError(
                "Password needs a number"
            )

        if not re.search(r"[^A-Za-z0-9]", value):
            raise ValueError(
                "Password needs a special character"
            )

        return value


# =========================================================
# LOGIN
# =========================================================

class LoginRequest(BaseModel):
    email: EmailStr

    password: str = Field(
        min_length=1,
        max_length=128,
    )


# =========================================================
# TWO-FACTOR AUTHENTICATION METHOD
# =========================================================

class TwoFactorMethodRequest(BaseModel):
    method: Literal["totp", "email"]


# =========================================================
# TWO-FACTOR VERIFICATION
# =========================================================

class TwoFactorVerifyRequest(BaseModel):
    code: str = Field(
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$",
    )


class TwoFactorChallengeResponse(BaseModel):
    requires_two_factor: bool = True

    challenge_token: str

    available_methods: list[
        Literal["totp", "email"]
    ]

    expires_in: int = Field(
        default=300,
        ge=1,
    )

    message: str | None = None


# =========================================================
# TWO-FACTOR ENROLLMENT
# =========================================================

class TotpSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    message: str


class TwoFactorSetupVerifyRequest(BaseModel):
    code: str = Field(
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$",
    )


class TwoFactorStatusResponse(BaseModel):
    two_factor_enabled: bool

    two_factor_method: Literal[
        "totp",
        "email",
    ] | None = None

    totp_enabled: bool
    email_otp_enabled: bool


# =========================================================
# EMAIL OTP
# =========================================================

class EmailOtpSendResponse(BaseModel):
    message: str
    expires_in: int = 300


class EmailOtpVerifyRequest(BaseModel):
    code: str = Field(
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$",
    )


# =========================================================
# USER RESPONSE
# =========================================================

class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str

    date_of_birth: date | None = None

    auth_provider: str = "email"

    email_verified: bool = False

    two_factor_enabled: bool = False

    two_factor_method: Literal[
        "totp",
        "email",
    ] | None = None

    totp_enabled: bool = False
    email_otp_enabled: bool = False

    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(
        from_attributes=True
    )

    @computed_field
    @property
    def age(self) -> int | None:
        return calculate_age(self.date_of_birth)


# =========================================================
# ACCESS TOKEN RESPONSE
# =========================================================

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# =========================================================
# PENDING REGISTRATION - START
# =========================================================

class RegistrationStartResponse(BaseModel):
    requires_email_verification: bool = True

    registration_token: str

    expires_in: int = 900

    message: str


# =========================================================
# PENDING REGISTRATION - EMAIL VERIFICATION
# =========================================================

class RegistrationEmailVerifyRequest(BaseModel):
    code: str = Field(
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$",
    )


class RegistrationEmailVerifyResponse(BaseModel):
    email_verified: bool = True

    requires_two_factor_setup: bool = True

    enrollment_token: str

    available_methods: list[
        Literal["totp", "email"]
    ] = Field(
        default_factory=lambda: ["totp", "email"]
    )

    message: str


class RegistrationResendOtpResponse(BaseModel):
    message: str

    expires_in: int = 300


# =========================================================
# PENDING REGISTRATION - TWO-FACTOR METHOD
# =========================================================

class RegistrationTwoFactorMethodRequest(BaseModel):
    method: Literal["totp", "email"]


# =========================================================
# PENDING REGISTRATION - TOTP SETUP
# =========================================================

class RegistrationTotpSetupResponse(BaseModel):
    secret: str

    provisioning_uri: str

    message: str


# =========================================================
# PENDING REGISTRATION - TWO-FACTOR VERIFICATION
# =========================================================

class RegistrationTwoFactorVerifyRequest(BaseModel):
    code: str = Field(
        min_length=6,
        max_length=6,
        pattern=r"^\d{6}$",
    )


# =========================================================
# PENDING REGISTRATION - COMPLETE
# =========================================================

class RegistrationCompleteResponse(BaseModel):
    registration_complete: bool = True

    access_token: str

    token_type: str = "bearer"

    user: UserResponse


# =========================================================
# SOCIAL AUTHENTICATION RESPONSE
# =========================================================

class OAuthLoginResponse(BaseModel):
    message: str

    requires_profile_completion: bool = False

    requires_two_factor: bool = False

    challenge_token: str | None = None

    available_methods: list[
        Literal["totp", "email"]
    ] = Field(default_factory=list)

    access_token: str | None = None

    token_type: str = "bearer"

    user: UserResponse | None = None
