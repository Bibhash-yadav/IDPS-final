import re
from datetime import date, datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    computed_field,
    field_validator,
)

from app.utils.age import calculate_age


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


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(
        min_length=1,
        max_length=128,
    )


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str

    date_of_birth: date | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)

    @computed_field
    @property
    def age(self) -> int | None:
        return calculate_age(self.date_of_birth)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
