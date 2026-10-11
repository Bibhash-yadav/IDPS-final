
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.security_rule import SecurityRule
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(prefix="/api/protection", tags=["Protection"])

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


class DomainRuleRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    rule_type: Literal["ALLOW", "BLOCK"]


def normalize_domain(value: str) -> str:
    domain = value.strip().lower()

    if "://" in domain or "/" in domain or "@" in domain:
        raise HTTPException(
            status_code=422,
            detail="Enter a domain only, for example example.com.",
        )

    if domain.endswith("."):
        domain = domain[:-1]

    if not DOMAIN_PATTERN.fullmatch(domain):
        raise HTTPException(
            status_code=422,
            detail="Invalid domain format.",
        )

    return domain


def serialize_rule(rule: SecurityRule) -> dict:
    return {
        "id": rule.id,
        "domain": rule.domain,
        "rule_type": rule.rule_type,
        "created_at": (
            rule.created_at.isoformat()
            if rule.created_at
            else None
        ),
    }


@router.get("/domains")
def list_domain_rules(
    rule_type: Literal["ALLOW", "BLOCK"] | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(SecurityRule).filter(
        SecurityRule.user_id == current_user.id
    )

    if rule_type:
        query = query.filter(SecurityRule.rule_type == rule_type)

    rules = query.order_by(SecurityRule.domain.asc()).all()

    return {"items": [serialize_rule(rule) for rule in rules]}


@router.post("/domains", status_code=201)
def add_domain_rule(
    payload: DomainRuleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    domain = normalize_domain(payload.domain)

    existing = db.query(SecurityRule).filter(
        SecurityRule.user_id == current_user.id,
        SecurityRule.domain == domain,
        SecurityRule.rule_type == payload.rule_type,
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="This domain rule already exists.",
        )

    rule = SecurityRule(
        user_id=current_user.id,
        domain=domain,
        rule_type=payload.rule_type,
    )

    db.add(rule)

    try:
        db.commit()
        db.refresh(rule)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="This domain rule already exists.",
        )

    return serialize_rule(rule)


@router.delete("/domains/{rule_id}")
def delete_domain_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rule = db.query(SecurityRule).filter(
        SecurityRule.id == rule_id,
        SecurityRule.user_id == current_user.id,
    ).first()

    if not rule:
        raise HTTPException(
            status_code=404,
            detail="Domain rule not found.",
        )

    db.delete(rule)
    db.commit()

    return {"message": "Domain rule deleted successfully."}
