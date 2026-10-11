
import ipaddress
import logging
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.security_event import SecurityEvent
from app.models.security_rule import SecurityRule
from app.models.protection_settings import ProtectionSettings
from app.models.user import User
from app.routes.auth import get_current_user
from app.detectors import (
    analyze_url,
    normalize_url,
    detect_malware,
    detect_phishing,
)
from app.services.risk_engine import (
    calculate_risk,
    apply_domain_rules,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/url",
    tags=["URL Security"],
)


class URLCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    age: int = Field(ge=1, le=120)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("URL cannot be empty")

        return value


@router.post("/check")
def check_url(
    data: URLCheckRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        # 1. Normalize and validate the URL.
        normalized_url = normalize_url(data.url)

        if not isinstance(normalized_url, str) or not normalized_url.strip():
            raise ValueError("A valid URL is required")

        normalized_url = normalized_url.strip()
        parsed = urlsplit(normalized_url)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported")

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("URL must contain a hostname")

        hostname = hostname.lower().rstrip(".")

        # Accessing parsed.port can raise ValueError for an invalid port.
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("URL contains an invalid port") from exc

        # 2. Basic protection against localhost and private IP targets.
        if hostname in {"localhost", "localhost.localdomain"}:
            raise ValueError("Localhost URLs are not allowed")

        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None

        if address is not None and not address.is_global:
            raise ValueError(
                "Private and non-public IP addresses are not allowed"
            )

        # Note: hostname validation alone does not prevent DNS rebinding.
        # Do not fetch the submitted URL directly without additional
        # network-level SSRF protections.

        # 3. Run local URL, malware, and phishing detectors.
        url_result = analyze_url(normalized_url)
        malware_result = detect_malware(normalized_url)
        phishing_result = detect_phishing(normalized_url)

        if not isinstance(url_result, dict):
            raise RuntimeError(
                "analyze_url() must return a dictionary"
            )

        if not isinstance(malware_result, dict):
            raise RuntimeError(
                "detect_malware() must return a dictionary"
            )

        if not isinstance(phishing_result, dict):
            raise RuntimeError(
                "detect_phishing() must return a dictionary"
            )

        # Ensure the domain saved in the event is a valid string.
        detected_domain = url_result.get("domain") or hostname

        if not isinstance(detected_domain, str):
            raise RuntimeError(
                "URL detector returned an invalid domain"
            )

        # No external reputation service is configured.
        reputation = "UNKNOWN"

        # 4. Load this user's protection settings.
        settings = (
            db.query(ProtectionSettings)
            .filter(
                ProtectionSettings.user_id == current_user.id
            )
            .first()
        )

        safe_browsing_enabled = (
            settings.safe_browsing
            if settings is not None
            else True
        )

        strict_mode_enabled = (
            settings.strict_mode
            if settings is not None
            else True
        )

        age_restriction_enabled = (
            settings.age_restriction
            if settings is not None
            else False
        )

        # 5. Calculate risk using the configured local detectors.
        result = calculate_risk(
            url_result=url_result,
            malware_result=malware_result,
            phishing_result=phishing_result,
            domain_reputation=reputation,
            strict_safe_browsing=(
                safe_browsing_enabled and strict_mode_enabled
            ),
            user_age=data.age,
        )

        if not isinstance(result, dict):
            raise RuntimeError(
                "Risk engine must return a dictionary"
            )

        required_result_keys = {
            "risk_score",
            "risk_level",
            "decision",
            "reasons",
            "malware_detected",
            "phishing_detected",
        }

        missing_keys = required_result_keys - result.keys()

        if missing_keys:
            raise RuntimeError(
                "Risk engine is missing required result fields: "
                + ", ".join(sorted(missing_keys))
            )

        result["safe_browsing_enabled"] = safe_browsing_enabled
        result["strict_mode_enabled"] = strict_mode_enabled
        result["age_restriction_enabled"] = age_restriction_enabled

        # 6. Load only the current user's domain rules.
        user_rules = (
            db.query(SecurityRule)
            .filter(
                SecurityRule.user_id == current_user.id
            )
            .all()
        )

        result = apply_domain_rules(
            result=result,
            hostname=hostname,
            rules=user_rules,
        )

        if not isinstance(result, dict):
            raise RuntimeError(
                "Domain rule engine must return a dictionary"
            )

        # No website age-classification service is configured.
        # Do not claim that a real age restriction was detected.
        result["age_restricted"] = False
        result["required_age"] = None
        result["user_age"] = data.age
        result["age_decision"] = "NOT_ESTABLISHED"

        # 7. Classify the event using the final decision.
        if result["malware_detected"]:
            event_type = "MALWARE_DETECTED"
        elif result["phishing_detected"]:
            event_type = "PHISHING_DETECTED"
        elif result.get("blocklisted", False):
            event_type = "DOMAIN_BLOCKLISTED"
        elif result["decision"] != "ALLOW":
            event_type = "SUSPICIOUS_URL"
        else:
            event_type = "URL_CHECKED"

        # 8. Save the security event.
        event = SecurityEvent(
            user_id=current_user.id,
            url=normalized_url,
            domain=detected_domain,
            event_type=event_type,
            source="URL_CHECK",
            risk_score=int(result["risk_score"]),
            risk_level=str(result["risk_level"]),
            decision=str(result["decision"]),
            reasons=result["reasons"],
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        # 9. Return the result to the frontend.
        decision = str(result["decision"]).upper()

        if decision == "BLOCK":
            recommendation = "Do not continue to this website."
        elif decision == "WARN":
            recommendation = "Proceed with caution."
        else:
            recommendation = (
                "No blocking indicators were found "
                "by the configured checks."
            )

        return {
            "check_id": event.id,
            "url": normalized_url,
            "domain": detected_domain,
            "https_enabled": bool(
                url_result.get("https_enabled", False)
            ),
            "ssl_valid": None,
            "ssl_status": "NOT_CHECKED",
            "malware": malware_result,
            "phishing": phishing_result,
            "url_analysis": url_result,
            "domain_reputation": reputation,
            "safe_browsing_enabled": safe_browsing_enabled,
            "strict_mode_enabled": strict_mode_enabled,
            "age_restriction_enabled": age_restriction_enabled,
            "age_restricted": False,
            "required_age": None,
            "user_age": data.age,
            "age_decision": "NOT_ESTABLISHED",
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "decision": decision,
            "blocklisted": result.get("blocklisted", False),
            "reasons": result["reasons"],
            "recommendation": recommendation,
            "analysis_method": "local_heuristics",
        }

    except HTTPException:
        db.rollback()
        raise

    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception(
            "Database error while saving URL analysis"
        )
        raise HTTPException(
            status_code=500,
            detail="Database error while saving URL analysis.",
        ) from exc

    except Exception as exc:
        db.rollback()
        logger.exception("URL analysis failed")
        raise HTTPException(
            status_code=500,
            detail=(
                "URL analysis failed. Check the backend terminal "
                "for the detailed error."
            ),
        ) from exc
