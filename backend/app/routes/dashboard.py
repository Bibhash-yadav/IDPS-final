
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"],
)


@router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Restrict statistics to the authenticated user's events.
    user_filter = SecurityEvent.user_id == current_user.id

    def count_events(*conditions) -> int:
        statement = select(func.count(SecurityEvent.id)).where(
            user_filter,
            *conditions,
        )
        return db.scalar(statement) or 0

    total = count_events()

    allowed = count_events(SecurityEvent.decision == "ALLOW")
    warned = count_events(SecurityEvent.decision == "WARN")
    blocked = count_events(SecurityEvent.decision == "BLOCK")

    malware = count_events(
        SecurityEvent.event_type == "MALWARE_DETECTED"
    )

    phishing = count_events(
        SecurityEvent.event_type == "PHISHING_DETECTED"
    )

    since = datetime.now(timezone.utc) - timedelta(days=7)

    recent_events = count_events(
        SecurityEvent.created_at >= since
    )

    return {
        "total_urls_checked": total,
        "safe_websites": allowed,
        "warnings": warned,
        "blocked_websites": blocked,
        "malware_detected": malware,
        "phishing_detected": phishing,
        "security_events_last_7_days": recent_events,
        "protection_status": "ACTIVE",
        "data_source": "postgresql",
    }


@router.get("/events")
def get_dashboard_events(
    limit: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    statement = (
        select(SecurityEvent)
        .where(SecurityEvent.user_id == current_user.id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
    )

    events = db.scalars(statement).all()

    return [
        {
            "id": event.id,
            "url": event.url,
            "domain": event.domain,
            "event_type": event.event_type,
            "source": getattr(event, "source", "URL_CHECK"),
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
    ]
