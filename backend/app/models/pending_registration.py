
from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PendingRegistration(Base):
    __tablename__ = "pending_registrations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    date_of_birth: Mapped[date] = mapped_column(
        Date,
        nullable=False,
    )

    email_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

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
        nullable=False,
    )

    email_otp_last_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    two_factor_method: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    totp_secret: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    totp_last_used_step: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
