from sqlalchemy import (
    DateTime,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class BlockedDomain(Base):
    __tablename__ = "blocked_domains"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    reason: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )