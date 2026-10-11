
import ipaddress
import logging
from datetime import date
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
    is_adult_content_url,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/url",
    tags=["URL Security"],
)


class URLCheckRequest(BaseModel):
    # Age is deliberately not accepted as an authoritative field.
    # Extra fields such as "age" from older frontends are ignored.
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("URL cannot be empty")

        return value


def calculate_registered_age(date_of_birth: date | None) -> int | None:
    """Calculate age using the date of birth saved in the database."""
    if date_of_birth is None:
        return None

    today = date.today()

    if date_of_birth > today:
        return None

    age = today.year - date_of_birth.year

    if (today.month, today.day) < (
        date_of_birth.month,
        date_of_birth.day,
    ):
        age -= 1

    return age if 0 <= age <= 120 else None


@router.post("/check")
def check_url(
    data: URLCheckRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        # 1. Derive age from the authenticated database user.
        # Never trust an age supplied by the browser.
        account_age = calculate_registered_age(
            current_user.date_of_birth
        )

        if account_age is None:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Your registered date of birth is missing or invalid. "
                    "Please update your account before checking websites."
                ),
            )

        # 2. Normalize and validate the submitted URL.
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

        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("URL contains an invalid port") from exc

        # Reject local hosts and non-public IP addresses.
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

        # Do not fetch submitted URLs without appropriate SSRF protection.
        # This endpoint performs analysis using the configured detectors.

        # 3. Run the configured detectors.
        url_result = analyze_url(normalized_url)
        malware_result = detect_malware(normalized_url)
        phishing_result = detect_phishing(normalized_url)

        if not isinstance(url_result, dict):
            raise RuntimeError("analyze_url() must return a dictionary")

        if not isinstance(malware_result, dict):
            raise RuntimeError("detect_malware() must return a dictionary")

        if not isinstance(phishing_result, dict):
            raise RuntimeError("detect_phishing() must return a dictionary")

        # Make the original URL available to the risk engine.
        url_result["url"] = normalized_url

        detected_domain = url_result.get("domain") or hostname

        if not isinstance(detected_domain, str):
            raise RuntimeError(
                "URL detector returned an invalid domain"
            )

        # This is a rule-based indicator, not a comprehensive content classifier.
        adult_match = is_adult_content_url(normalized_url)

        # 4. Load this user's protection settings.
        settings = (
            db.query(ProtectionSettings)
            .filter(
                ProtectionSettings.user_id == current_user.id
            )
            .first()
        )

        safe_browsing_enabled = (
            settings.safe_browsing if settings is not None else True
        )

        strict_mode_enabled = (
            settings.strict_mode if settings is not None else True
        )

        age_restriction_enabled = (
            settings.age_restriction if settings is not None else True
        )

        # 5. Calculate risk using the registered age.
        result = calculate_risk(
            url_result=url_result,
            malware_result=malware_result,
            phishing_result=phishing_result,
            domain_reputation="UNKNOWN",
            strict_safe_browsing=(
                safe_browsing_enabled and strict_mode_enabled
            ),
            user_age=account_age,
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

        result["adult_content_detected"] = adult_match
        result["user_age"] = account_age

        # Apply the age rule only when age protection is enabled.
        if adult_match and age_restriction_enabled:
            result["age_restricted"] = True
            result["required_age"] = 18
            result["age_decision"] = (
                "BLOCK" if account_age < 18 else "ALLOW"
            )

            if account_age < 18:
                result["decision"] = "BLOCK"
                result["risk_score"] = max(
                    int(result.get("risk_score", 0)),
                    100,
                )
                result["risk_level"] = "CRITICAL"

                reasons = list(result.get("reasons") or [])
                reasons.extend([
                    "The URL matches a configured adult-content rule.",
                    "Access is blocked because the registered account age is below 18.",
                ])
                result["reasons"] = list(dict.fromkeys(reasons))

                detection_status = result.get("detection_status") or {}
                if isinstance(detection_status, dict):
                    result["detection_status"] = {
                        **detection_status,
                        "age_restriction": "BLOCK_UNDER_18",
                    }
        else:
            result["age_restricted"] = False
            result["required_age"] = None
            result["age_decision"] = "NOT_ESTABLISHED"

        result["safe_browsing_enabled"] = safe_browsing_enabled
        result["strict_mode_enabled"] = strict_mode_enabled
        result["age_restriction_enabled"] = age_restriction_enabled

        # 6. Apply only this user's saved domain rules.
        user_rules = (
            db.query(SecurityRule)
            .filter(SecurityRule.user_id == current_user.id)
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

        # Reassert the age block after custom domain rules.
        # A user-created ALLOW rule must not override it.
        if (
            adult_match
            and age_restriction_enabled
            and account_age < 18
        ):
            result["decision"] = "BLOCK"
            result["risk_level"] = "CRITICAL"
            result["risk_score"] = max(
                int(result.get("risk_score", 0)),
                100,
            )
            result["adult_content_detected"] = True
            result["age_restricted"] = True
            result["required_age"] = 18
            result["user_age"] = account_age
            result["age_decision"] = "BLOCK"

        # 7. Classify the security event.
        if result.get("malware_detected"):
            event_type = "MALWARE_DETECTED"
        elif result.get("phishing_detected"):
            event_type = "PHISHING_DETECTED"
        elif (
            result.get("adult_content_detected")
            and age_restriction_enabled
            and account_age < 18
        ):
            event_type = "AGE_RESTRICTED_CONTENT_BLOCKED"
        elif result.get("blocklisted", False):
            event_type = "DOMAIN_BLOCKLISTED"
        elif str(result.get("decision", "")).upper() != "ALLOW":
            event_type = "SUSPICIOUS_URL"
        else:
            event_type = "URL_CHECKED"

        # 8. Save the security event.
        event = SecurityEvent(
            user_id=current_user.id,
            url=normalized_url,
            domain=detected_domain,
            event_type=event_type,
            risk_score=int(result["risk_score"]),
            risk_level=str(result["risk_level"]),
            decision=str(result["decision"]).upper(),
            reasons=result.get("reasons", []),
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        # 9. Build the response for the frontend.
        decision = str(result["decision"]).upper()

        if decision == "BLOCK":
            recommendation = "Do not continue to this website."
        elif decision == "WARN":
            recommendation = "Proceed with caution."
        else:
            recommendation = (
                "No blocking indicators were found by the configured checks."
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
            "domain_reputation": "UNKNOWN",
            "safe_browsing_enabled": safe_browsing_enabled,
            "strict_mode_enabled": strict_mode_enabled,
            "age_restriction_enabled": age_restriction_enabled,
            "adult_content_detected": bool(
                result.get("adult_content_detected", False)
            ),
            "age_restricted": bool(
                result.get("age_restricted", False)
            ),
            "required_age": result.get("required_age"),
            "user_age": account_age,
            "age_decision": result.get(
                "age_decision", "NOT_ESTABLISHED"
            ),
            "risk_score": int(result["risk_score"]),
            "risk_level": result["risk_level"],
            "decision": decision,
            "blocklisted": result.get("blocklisted", False),
            "reasons": result.get("reasons", []),
            "recommendation": recommendation,
            "analysis_method": result.get(
                "analysis_method", "local_heuristics"
            ),
            "test_mode": result.get("test_mode", False),
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
        logger.exception("Database error while saving URL analysis")
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
