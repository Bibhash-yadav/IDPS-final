
from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(Base):
    __tablename__ = "users"

    # =====================================================
    # BASIC USER INFORMATION
    # =====================================================

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    password_hash: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    role: Mapped[str] = mapped_column(
        String(20),
        default="USER",
        nullable=False,
    )

    date_of_birth: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    # =====================================================
    # SOCIAL AUTHENTICATION PROVIDERS
    # =====================================================

    auth_provider: Mapped[str] = mapped_column(
        String(30),
        default="email",
        nullable=False,
    )

    google_id: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        nullable=True,
        index=True,
    )

    github_id: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        nullable=True,
        index=True,
    )

    # =====================================================
    # EMAIL VERIFICATION
    # =====================================================

    email_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        nullable=False,
    )

    # =====================================================
    # TWO-FACTOR AUTHENTICATION SETTINGS
    # =====================================================

    two_factor_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        nullable=False,
    )

    # Supported values:
    # "totp"  = Google Authenticator
    # "email" = Email OTP

    two_factor_method: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    # =====================================================
    # GOOGLE AUTHENTICATOR (TOTP)
    # =====================================================

    totp_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        nullable=False,
    )

    # Store the encrypted TOTP secret, not plaintext.
    # Encryption/decryption is handled by security/auth.py.

    totp_secret: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Tracks the last accepted TOTP time step
    # to help prevent reuse of an already accepted code.

    totp_last_used_step: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    # =====================================================
    # EMAIL OTP SETTINGS
    # =====================================================

    email_otp_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        nullable=False,
    )

    # Store an HMAC hash of the OTP, never the plain OTP.

    email_otp_hash: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    email_otp_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    email_otp_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )

    email_otp_last_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # =====================================================
    # ACCOUNT TIMESTAMPS
    # =====================================================

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
