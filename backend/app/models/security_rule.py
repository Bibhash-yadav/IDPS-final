
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SecurityRule(Base):
    __tablename__ = "security_rules"

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "domain",
            "rule_type",
            name="uq_security_rule_user_domain_type",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    domain: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        index=True,
    )

    rule_type: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
