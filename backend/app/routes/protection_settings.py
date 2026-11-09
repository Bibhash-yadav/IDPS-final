from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.protection_settings import ProtectionSettings
from app.models.allowed_domain import AllowedDomain
from app.models.blocked_domain import BlockedDomain
from app.models.user import User
from app.routes.auth import get_current_user


router = APIRouter(
    prefix="/api/protection",
    tags=["Protection Settings"],
)


# ============================================================
# PYDANTIC SCHEMAS
# ============================================================

class ProtectionSettingsUpdate(BaseModel):
    safe_browsing: bool
    strict_mode: bool
    age_restriction: bool
    minimum_age: int = Field(ge=1, le=120)


class ProtectionSettingsResponse(BaseModel):
    safe_browsing: bool
    strict_mode: bool
    age_restriction: bool
    minimum_age: int


class DomainCreate(BaseModel):
    domain: str = Field(min_length=1, max_length=255)
    reason: str | None = Field(default=None, max_length=500)


class DomainResponse(BaseModel):
    id: int
    domain: str
    reason: str | None
    created_at: str


class DomainListsResponse(BaseModel):
    allowed_domains: list[DomainResponse]
    blocked_domains: list[DomainResponse]


# ============================================================
# HELPERS
# ============================================================

def settings_to_dict(settings: ProtectionSettings) -> dict:
    return {
        "safe_browsing": settings.safe_browsing,
        "strict_mode": settings.strict_mode,
        "age_restriction": settings.age_restriction,
        "minimum_age": settings.minimum_age,
    }


def normalize_domain(value: str) -> str:
    """
    Normalize a domain before saving.

    Accepts:
      example.com
      https://example.com
      www.example.com
      example.com/path

    Stores only the hostname.
    """

    value = value.strip().lower()

    if not value:
        raise HTTPException(
            status_code=400,
            detail="Domain cannot be empty.",
        )

    if "://" not in value:
        value = "https://" + value

    try:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported protocol")

        if not parsed.hostname:
            raise ValueError("Missing hostname")

        if parsed.username or parsed.password:
            raise ValueError("Credentials are not allowed")

        hostname = parsed.hostname.lower().rstrip(".")

        if len(hostname) > 255:
            raise ValueError("Hostname is too long")

        if hostname == "localhost":
            raise ValueError("Localhost cannot be added")

        if hostname.replace(".", "").isdigit():
            raise ValueError("IP addresses are not accepted as domains")

        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(
                character.isalnum() or character == "-"
                for character in label
            )
            for label in hostname.split(".")
        ):
            raise ValueError("Invalid domain format")

        if "." not in hostname:
            raise ValueError("Enter a valid domain name")

        return hostname

    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail="Enter a valid domain, such as example.com.",
        )


def domain_to_dict(domain) -> dict:
    return {
        "id": domain.id,
        "domain": domain.domain,
        "reason": domain.reason,
        "created_at": (
            domain.created_at.isoformat()
            if domain.created_at
            else ""
        ),
    }


def add_domain(db: Session, model, data: DomainCreate):
    domain_name = normalize_domain(data.domain)

    existing = (
        db.query(model)
        .filter(
            func.lower(model.domain) == domain_name
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"{domain_name} already exists.",
        )

    record = model(
        domain=domain_name,
        reason=data.reason.strip() if data.reason else None,
    )

    try:
        db.add(record)
        db.commit()
        db.refresh(record)

        return domain_to_dict(record)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail=f"{domain_name} already exists.",
        )

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Could not save domain.",
        ) from exc


def delete_domain(db: Session, model, domain_id: int):
    record = (
        db.query(model)
        .filter(model.id == domain_id)
        .first()
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Domain not found.",
        )

    try:
        db.delete(record)
        db.commit()

        return {
            "success": True,
            "message": f"{record.domain} deleted successfully.",
        }

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Could not delete domain.",
        ) from exc


# ============================================================
# PROTECTION SETTINGS
# ============================================================

@router.get(
    "/settings",
    response_model=ProtectionSettingsResponse,
)
def get_protection_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return the logged-in user's protection settings."""

    try:
        settings = (
            db.query(ProtectionSettings)
            .filter(
                ProtectionSettings.user_id == current_user.id
            )
            .first()
        )

        if settings is None:
            settings = ProtectionSettings(
                user_id=current_user.id,
                safe_browsing=True,
                strict_mode=True,
                age_restriction=False,
                minimum_age=18,
            )

            db.add(settings)
            db.commit()
            db.refresh(settings)

        return settings_to_dict(settings)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Could not load protection settings.",
        ) from exc


@router.put(
    "/settings",
    response_model=ProtectionSettingsResponse,
)
def update_protection_settings(
    data: ProtectionSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create or update the logged-in user's protection settings."""

    try:
        settings = (
            db.query(ProtectionSettings)
            .filter(
                ProtectionSettings.user_id == current_user.id
            )
            .first()
        )

        if settings is None:
            settings = ProtectionSettings(
                user_id=current_user.id,
                safe_browsing=data.safe_browsing,
                strict_mode=data.strict_mode,
                age_restriction=data.age_restriction,
                minimum_age=data.minimum_age,
            )

            db.add(settings)

        else:
            settings.safe_browsing = data.safe_browsing
            settings.strict_mode = data.strict_mode
            settings.age_restriction = data.age_restriction
            settings.minimum_age = data.minimum_age

        db.commit()
        db.refresh(settings)

        return settings_to_dict(settings)

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Could not save protection settings.",
        ) from exc


# ============================================================
# GET ALLOWED AND BLOCKED DOMAINS
# ============================================================

@router.get("/domains", response_model=DomainListsResponse)
def get_domains(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return all allowed and blocked domains.

    These lists are shared between authenticated users.
    """

    try:
        allowed = (
            db.query(AllowedDomain)
            .order_by(AllowedDomain.created_at.desc())
            .all()
        )

        blocked = (
            db.query(BlockedDomain)
            .order_by(BlockedDomain.created_at.desc())
            .all()
        )

        return {
            "allowed_domains": [
                domain_to_dict(item) for item in allowed
            ],
            "blocked_domains": [
                domain_to_dict(item) for item in blocked
            ],
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not load domain lists.",
        ) from exc


# ============================================================
# ALLOWED DOMAINS
# ============================================================

@router.get("/allowed-domains")
def get_allowed_domains(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        domains = (
            db.query(AllowedDomain)
            .order_by(AllowedDomain.created_at.desc())
            .all()
        )

        return {
            "success": True,
            "domains": [
                domain_to_dict(item) for item in domains
            ],
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not load allowed domains.",
        ) from exc


@router.post(
    "/allowed-domains",
    status_code=status.HTTP_201_CREATED,
)
def create_allowed_domain(
    data: DomainCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = add_domain(db, AllowedDomain, data)

    return {
        "success": True,
        "message": "Domain added to allowed list.",
        "domain": result,
    }


@router.delete("/allowed-domains/{domain_id}")
def remove_allowed_domain(
    domain_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = delete_domain(db, AllowedDomain, domain_id)

    return result


# ============================================================
# BLOCKED DOMAINS
# ============================================================

@router.get("/blocked-domains")
def get_blocked_domains(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        domains = (
            db.query(BlockedDomain)
            .order_by(BlockedDomain.created_at.desc())
            .all()
        )

        return {
            "success": True,
            "domains": [
                domain_to_dict(item) for item in domains
            ],
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not load blocked domains.",
        ) from exc


@router.post(
    "/blocked-domains",
    status_code=status.HTTP_201_CREATED,
)
def create_blocked_domain(
    data: DomainCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = add_domain(db, BlockedDomain, data)

    return {
        "success": True,
        "message": "Domain added to blocked list.",
        "domain": result,
    }


@router.delete("/blocked-domains/{domain_id}")
def remove_blocked_domain(
    domain_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = delete_domain(db, BlockedDomain, domain_id)

    return result