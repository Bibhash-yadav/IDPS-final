
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # Identifies where the security event originated.
    source: Mapped[str] = mapped_column(
        String(50),
        default="URL_CHECK",
        server_default="URL_CHECK",
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        default="LOW",
        server_default="LOW",
        nullable=False,
    )

    decision: Mapped[str] = mapped_column(
        String(20),
        default="WARN",
        server_default="WARN",
        nullable=False,
    )

    reasons: Mapped[list] = mapped_column(
        JSON,
        default=list,
        server_default="[]",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
