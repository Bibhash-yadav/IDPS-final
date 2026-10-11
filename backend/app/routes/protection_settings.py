from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.protection_settings import ProtectionSettings
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(
    prefix="/api/protection",
    tags=["Protection Settings"],
)


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


def settings_to_dict(settings: ProtectionSettings) -> dict:
    return {
        "safe_browsing": settings.safe_browsing,
        "strict_mode": settings.strict_mode,
        "age_restriction": settings.age_restriction,
        "minimum_age": settings.minimum_age,
    }


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
