
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.security_event import SecurityEvent
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api/events", tags=["Security Events"])


@router.get("")
def list_security_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: Optional[str] = Query(None, max_length=200),
    risk_level: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == current_user.id
    )

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                SecurityEvent.url.ilike(term),
                SecurityEvent.domain.ilike(term),
                SecurityEvent.event_type.ilike(term),
            )
        )

    if risk_level:
        query = query.filter(
            func.upper(SecurityEvent.risk_level) == risk_level.upper()
        )

    if decision:
        query = query.filter(
            func.upper(SecurityEvent.decision) == decision.upper()
        )

    total = query.count()

    events = (
        query.order_by(SecurityEvent.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "items": [
            {
                "id": event.id,
                "url": event.url,
                "domain": event.domain,
                "event_type": event.event_type,
                "risk_score": event.risk_score,
                "risk_level": event.risk_level,
                "decision": event.decision,
                "reasons": event.reasons or [],
                "created_at": (
                    event.created_at.isoformat()
                    if event.created_at
                    else None
                ),
            }
            for event in events
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": (total + page_size - 1) // page_size,
    }
