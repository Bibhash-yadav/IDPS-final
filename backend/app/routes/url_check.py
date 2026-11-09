
import asyncio
import ipaddress
import logging
import socket

from datetime import date
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db

from app.services.cloudflare_service import CloudflareService
from app.services.risk_engine import (
    calculate_risk,
    apply_domain_rules,
    is_adult_content_url,
    get_google_safe_browsing_test_type,
)

from app.models.security_event import SecurityEvent
from app.models.security_rule import SecurityRule
from app.models.protection_settings import ProtectionSettings
from app.models.user import User

from app.routes.auth import get_current_user

from app.detectors import analyze_url_signals


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/url",
    tags=["URL Security"],
)


# ---------------------------------------------------------
# REQUEST MODEL
# ---------------------------------------------------------

class URLCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("URL cannot be empty")

        return value


# ---------------------------------------------------------
# AGE CALCULATION
# ---------------------------------------------------------

def calculate_registered_age(
    date_of_birth: date | None,
) -> int | None:

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


# ---------------------------------------------------------
# URL NORMALIZATION
# ---------------------------------------------------------

def normalize_checked_url(value: str) -> str:

    value = value.strip()

    if not value:
        raise ValueError("URL cannot be empty.")

    if not value.lower().startswith(("http://", "https://")):
        value = "https://" + value

    parsed = urlsplit(value)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("URL must contain a valid hostname.")

    if parsed.username or parsed.password:
        raise ValueError(
            "URLs containing embedded usernames or passwords are not allowed."
        )

    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port.") from exc

    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path or "/",
        parsed.query,
        parsed.fragment,
    ))


# ---------------------------------------------------------
# HOSTNAME VALIDATION
# ---------------------------------------------------------

def validate_hostname(normalized_url: str):

    parsed = urlsplit(normalized_url)

    hostname = (parsed.hostname or "").lower().rstrip(".")

    if not hostname:
        raise ValueError("URL must contain a hostname.")

    if hostname in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost URLs are not allowed.")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None and not address.is_global:
        raise ValueError(
            "Private and non-public IP addresses are not allowed."
        )

    return parsed, hostname


# ---------------------------------------------------------
# DNS RESOLUTION
# ---------------------------------------------------------

def resolve_domain(hostname: str) -> list[str]:

    results = socket.getaddrinfo(
        hostname,
        None,
        type=socket.SOCK_STREAM,
    )

    addresses = set()

    for result in results:

        raw_ip = result[4][0]

        try:
            parsed_ip = ipaddress.ip_address(raw_ip)

            if parsed_ip.is_global:
                addresses.add(str(parsed_ip))

        except ValueError:
            continue

    return sorted(addresses)


async def check_dns(hostname: str) -> dict:

    try:

        addresses = await asyncio.wait_for(
            asyncio.to_thread(resolve_domain, hostname),
            timeout=6,
        )

        if addresses:
            return {
                "status": "RESOLVED",
                "resolved": True,
                "resolved_ips": addresses,
                "message": "Hostname resolved successfully.",
            }

        return {
            "status": "NOT_RESOLVED",
            "resolved": False,
            "resolved_ips": [],
            "message": "No public IP addresses were resolved.",
        }

    except asyncio.TimeoutError:

        return {
            "status": "TIMEOUT",
            "resolved": False,
            "resolved_ips": [],
            "message": "DNS resolution timed out.",
        }

    except socket.gaierror:

        return {
            "status": "NOT_RESOLVED",
            "resolved": False,
            "resolved_ips": [],
            "message": "DNS could not resolve this hostname.",
        }

    except Exception:

        logger.exception("DNS check failed for %s", hostname)

        return {
            "status": "ERROR",
            "resolved": False,
            "resolved_ips": [],
            "message": "DNS verification could not be completed.",
        }


# ---------------------------------------------------------
# RISK ADJUSTMENT
# ---------------------------------------------------------

def _risk_level_from_score(score: int) -> str:
    """Keep risk labels consistent with the configured score thresholds."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def add_security_warning(
    result: dict,
    message: str,
    minimum_score: int = 60,
):
    """Add a warning without mislabelling the score or overriding BLOCK."""
    reasons = result.get("reasons") or []

    if isinstance(reasons, str):
        reasons = [reasons]

    reasons.append(message)
    result["reasons"] = list(dict.fromkeys(str(item) for item in reasons if item))

    current_score = max(0, min(100, int(result.get("risk_score", 0) or 0)))
    new_score = max(current_score, minimum_score)
    result["risk_score"] = new_score

    if str(result.get("decision", "")).upper() != "BLOCK":
        result["decision"] = "WARN"

    result["risk_level"] = _risk_level_from_score(new_score)
    return result


def apply_ssl_risk(result: dict, signals: dict):
    """Only failed or unavailable TLS verification changes the risk result."""
    ssl_status = str(signals.get("ssl_status", "NOT_CHECKED")).upper()

    if ssl_status in {
        "HOSTNAME_MISMATCH",
        "EXPIRED",
        "NOT_YET_VALID",
        "INVALID",
        "TLS_ERROR",
        "INVALID_HOSTNAME",
    }:
        result = add_security_warning(
            result,
            f"SSL/TLS validation failed: {ssl_status}.",
            60,
        )
    elif ssl_status in {"TIMEOUT", "UNAVAILABLE", "ERROR"}:
        result = add_security_warning(
            result,
            "SSL certificate could not be verified. Do not assume HTTPS is safe.",
            50,
        )

    detection_status = result.setdefault("detection_status", {})
    detection_status["ssl_tls"] = ssl_status
    detection_status["https"] = (
        "ENABLED" if signals.get("https_enabled") else "NOT_ENABLED"
    )
    return result


def apply_dns_risk(result: dict, dns_result: dict):
    """DNS failures warrant caution, but are not proof of malicious activity."""
    if not dns_result.get("resolved"):
        result = add_security_warning(
            result,
            "DNS verification could not confirm a public IP address for this hostname.",
            50,
        )

    result.setdefault("detection_status", {})["dns"] = dns_result.get(
        "status", "UNKNOWN"
    )
    return result


# ---------------------------------------------------------
# MAIN URL CHECK ENDPOINT
# ---------------------------------------------------------

@router.post("/check")
async def check_url(
    data: URLCheckRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    try:

        # -------------------------------------------------
        # 1. USER AGE
        # -------------------------------------------------

        account_age = calculate_registered_age(
            current_user.date_of_birth
        )

        if account_age is None:
            raise HTTPException(
                status_code=403,
                detail="Your registered date of birth is missing or invalid.",
            )

        # -------------------------------------------------
        # 2. NORMALIZE URL
        # -------------------------------------------------

        complete_url = normalize_checked_url(data.url)

        parsed, hostname = validate_hostname(complete_url)

        # -------------------------------------------------
        # 3. DNS CHECK
        # -------------------------------------------------

        dns_result = await check_dns(hostname)

        # -------------------------------------------------
        # 4. EXISTING DETECTOR + REAL SSL CHECK
        # -------------------------------------------------

        signals = await analyze_url_signals(
            url=complete_url,
            user_age=account_age,
        )

        if not isinstance(signals, dict):
            raise RuntimeError(
                "analyze_url_signals() must return a dictionary."
            )

        logger.info(
            "URL analysis completed for %s. SSL: %s",
            hostname,
            signals.get("ssl_status"),
        )

        # -------------------------------------------------
        # 5. ADAPT SIGNALS TO EXISTING RISK ENGINE
        # -------------------------------------------------

        url_result = {
            "url": complete_url,
            "domain": hostname,
            "https_enabled": signals.get("https_enabled", complete_url.lower().startswith("https://")),
            "ssl_valid": signals.get("ssl_valid"),
            "ssl_status": signals.get("ssl_status", "NOT_CHECKED"),
            "suspicious_url": signals.get("suspicious_url", False),
            "domain_reputation": signals.get("domain_reputation", "UNKNOWN"),
            # The risk engine reads risk_contribution and findings.
            # A clean URL contributes zero; suspicious structure contributes 20.
            "risk_contribution": 20 if signals.get("suspicious_url", False) else 0,
            "findings": (
                [signals.get("reasons", [])]
                if signals.get("suspicious_url", False) and signals.get("reasons")
                else []
            ),
            "reasons": signals.get("reasons", []),
        }

        malware_result = {
            "malware_detected": signals.get("malware_detected", False),
            "malware_confidence": signals.get("malware_confidence", 0),
            "malware_type": signals.get("malware_type"),
            "reason": (
                "Malware indicators detected."
                if signals.get("malware_detected", False)
                else "No configured malware pattern matched."
            ),
        }

        phishing_result = {
            "phishing_detected": signals.get("phishing_detected", False),
            "phishing_confidence": signals.get("phishing_confidence", 0),
            "findings": (
                ["Phishing indicators detected."]
                if signals.get("phishing_detected", False)
                else []
            ),
        }

        # -------------------------------------------------
        # 6. CLOUDFLARE INTEGRATION
        # -------------------------------------------------

        cloudflare_result = {
            "enabled": False,

            "url_scan": {
                "status": "unavailable",
                "scan_id": None,
                "url": complete_url,
                "message": "Cloudflare URL Scanner unavailable.",
            },

            "domain_intelligence": {
                "status": "unavailable",
                "domain": hostname,
                "intelligence": None,
                "message": "Cloudflare domain intelligence unavailable.",
            },
        }

        try:

            cloudflare = CloudflareService()

            scan_response, domain_response = await asyncio.gather(
                cloudflare.scan_url(complete_url),
                cloudflare.get_domain_intelligence(hostname),
                return_exceptions=True,
            )

            if not isinstance(scan_response, Exception):
                cloudflare_result["enabled"] = True

                cloudflare_result["url_scan"] = {
                    "status": "submitted",
                    "scan_id": scan_response.get("scan_id"),
                    "url": scan_response.get("url", complete_url),
                    "visibility": scan_response.get("visibility"),
                    "message": scan_response.get(
                        "message",
                        "URL submitted to Cloudflare Scanner.",
                    ),
                }
            else:
                logger.warning(
                    "Cloudflare URL scan failed: %s",
                    scan_response,
                )

            if not isinstance(domain_response, Exception):

                intelligence = domain_response.get(
                    "intelligence",
                    domain_response.get("result"),
                )

                cloudflare_result["domain_intelligence"] = {
                    "status": "available",
                    "domain": hostname,
                    "intelligence": intelligence,
                    "message": "Domain intelligence retrieved.",
                }

                cloudflare_result["enabled"] = True

            else:
                logger.warning(
                    "Cloudflare domain lookup failed: %s",
                    domain_response,
                )

        except Exception:
            logger.exception("Cloudflare integration error")

        # -------------------------------------------------
        # 7. USER PROTECTION SETTINGS
        # -------------------------------------------------

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
            else True
        )

        # -------------------------------------------------
        # 8. ADULT CONTENT CHECK
        # -------------------------------------------------

        adult_match = is_adult_content_url(complete_url)

        # -------------------------------------------------
        # 9. EXISTING RISK ENGINE
        # -------------------------------------------------

        safe_browsing_test_type = get_google_safe_browsing_test_type(complete_url)

        result = calculate_risk(
            url_result=url_result,
            malware_result=malware_result,
            phishing_result=phishing_result,
            domain_reputation=signals.get("domain_reputation", "UNKNOWN"),
            strict_safe_browsing=(
                safe_browsing_enabled and strict_mode_enabled
            ),
            user_age=account_age,
            # Pass the real certificate verification result into risk_engine.
            # Without these arguments, risk_engine defaults to NOT_CHECKED
            # and can incorrectly add 50 risk points to a valid HTTPS site.
            ssl_valid=signals.get("ssl_valid"),
            ssl_status=signals.get("ssl_status", "NOT_CHECKED"),
            ssl_error=signals.get("ssl_error"),
        )

        if not isinstance(result, dict):
            raise RuntimeError(
                "calculate_risk() must return a dictionary."
            )

        # Google's published test URLs are classified by the risk engine.
        # Mirror that classification in the API response and saved event.
        malware_detected = bool(result.get("malware_detected", signals.get("malware_detected", False)))
        phishing_detected = bool(result.get("phishing_detected", signals.get("phishing_detected", False)))

        if safe_browsing_test_type:
            malware_detected = safe_browsing_test_type == "MALWARE"
            phishing_detected = safe_browsing_test_type == "PHISHING"
            malware_result["malware_detected"] = malware_detected
            malware_result["malware_confidence"] = 100 if malware_detected else 0
            malware_result["reason"] = (
                "Google Safe Browsing malware test case matched."
                if malware_detected else "No malware test case matched."
            )
            phishing_result["phishing_detected"] = phishing_detected
            phishing_result["phishing_confidence"] = 100 if phishing_detected else 0
            phishing_result["findings"] = (
                ["Google Safe Browsing phishing test case matched."]
                if phishing_detected else []
            )

        logger.info(
            "Risk calculation for %s: score=%s level=%s decision=%s "
            "ssl=%s dns=%s reputation=%s url_contribution=%s",
            hostname,
            result.get("risk_score"),
            result.get("risk_level"),
            result.get("decision"),
            signals.get("ssl_status"),
            dns_result.get("status"),
            signals.get("domain_reputation"),
            url_result.get("risk_contribution"),
        )

        required_keys = {
            "risk_score",
            "risk_level",
            "decision",
            "reasons",
        }

        missing_keys = required_keys - result.keys()

        if missing_keys:
            raise RuntimeError(
                "Risk engine missing fields: "
                + ", ".join(sorted(missing_keys))
            )

        # -------------------------------------------------
        # 10. AGE RESTRICTION
        # -------------------------------------------------

        if adult_match and age_restriction_enabled:

            result["age_restricted"] = True
            result["required_age"] = 18

            if account_age < 18:

                result["decision"] = "BLOCK"
                result["risk_score"] = 100
                result["risk_level"] = "CRITICAL"
                result["age_decision"] = "BLOCK"

                reasons = result.get("reasons") or []

                if isinstance(reasons, str):
                    reasons = [reasons]

                reasons.append(
                    "Access blocked because the account age is below 18."
                )

                result["reasons"] = list(dict.fromkeys(reasons))

            else:
                result["age_decision"] = "ALLOW"

        else:

            result["age_restricted"] = False
            result["required_age"] = None
            result["age_decision"] = "NOT_ESTABLISHED"

        # -------------------------------------------------
        # 11. CUSTOM DOMAIN RULES
        # -------------------------------------------------

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
                "apply_domain_rules() must return a dictionary."
            )

        # Do not allow custom ALLOW rules to override an age block.

        if (
            adult_match
            and age_restriction_enabled
            and account_age < 18
        ):

            result["decision"] = "BLOCK"
            result["risk_score"] = 100
            result["risk_level"] = "CRITICAL"
            result["age_decision"] = "BLOCK"

        # -------------------------------------------------
        # 12. APPLY SSL AND DNS RISK
        # -------------------------------------------------

        result = apply_ssl_risk(result, signals)

        result = apply_dns_risk(result, dns_result)

        # -------------------------------------------------
        # 13. CLASSIFY EVENT
        # -------------------------------------------------

        if malware_detected:
            event_type = "MALWARE_DETECTED"

        elif phishing_detected:
            event_type = "PHISHING_DETECTED"

        elif adult_match and age_restriction_enabled and account_age < 18:
            event_type = "AGE_RESTRICTED_CONTENT_BLOCKED"

        elif signals.get("ssl_valid") is False:
            event_type = "SSL_CERTIFICATE_INVALID"

        elif not dns_result["resolved"]:
            event_type = "DNS_VERIFICATION_FAILED"

        elif result["decision"] != "ALLOW":
            event_type = "SUSPICIOUS_URL"

        else:
            event_type = "URL_CHECKED"

        # -------------------------------------------------
        # 14. SAVE SECURITY EVENT
        # -------------------------------------------------

        reasons = result.get("reasons") or []

        if isinstance(reasons, str):
            reasons = [reasons]

        event = SecurityEvent(
            user_id=current_user.id,
            url=complete_url,
            domain=hostname,
            event_type=event_type,
            risk_score=int(result["risk_score"]),
            risk_level=str(result["risk_level"]),
            decision=str(result["decision"]).upper(),
            reasons=reasons,
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        # -------------------------------------------------
        # 15. RECOMMENDATION
        # -------------------------------------------------

        decision = str(result["decision"]).upper()

        if decision == "BLOCK":
            recommendation = "Do not continue to this website."

        elif decision == "WARN":
            recommendation = (
                "Proceed with caution. One or more security checks "
                "found problems or could not verify the website."
            )

        else:
            recommendation = (
                "No blocking indicators were found by the configured checks. "
                "This does not guarantee that the website is safe."
            )

        # -------------------------------------------------
        # 16. FINAL API RESPONSE
        # -------------------------------------------------

        return {
            "check_id": event.id,

            "url": complete_url,

            "domain": hostname,

            "protocol": parsed.scheme,

            "hostname": hostname,

            "path": parsed.path or "/",

            "query": parsed.query,

            # DNS
            "dns_status": dns_result["status"],

            "dns_resolved": dns_result["resolved"],

            "resolved_ips": dns_result["resolved_ips"],

            "dns_message": dns_result["message"],

            # HTTPS and SSL
            "https_enabled": signals.get("https_enabled", complete_url.lower().startswith("https://")),

            "ssl_valid": signals.get("ssl_valid"),

            "ssl_status": signals.get("ssl_status", "NOT_CHECKED"),

            "ssl_error": signals.get("ssl_error"),

            "ssl_message": signals.get("ssl_message"),

            # Malware
            "malware": malware_result,

            "malware_detected": malware_detected,

            "malware_confidence": signals.get("malware_confidence", 0),

            # Phishing
            "phishing": phishing_result,

            "phishing_detected": phishing_detected,

            "phishing_confidence": signals.get("phishing_confidence", 0),

            # Domain reputation
            "domain_reputation": signals.get("domain_reputation", "UNKNOWN"),

            "suspicious_url": signals.get("suspicious_url", False),

            # Age restrictions
            "adult_content_detected": adult_match,

            "age_restricted": result.get("age_restricted", False),

            "required_age": result.get("required_age"),

            "user_age": account_age,

            "age_decision": result.get("age_decision"),

            # Settings
            "safe_browsing_enabled": safe_browsing_enabled,

            "strict_mode_enabled": strict_mode_enabled,

            "age_restriction_enabled": age_restriction_enabled,

            # Risk
            "risk_score": int(result["risk_score"]),

            "risk_level": result["risk_level"],

            "decision": str(result["decision"]).upper(),

            "reasons": result.get("reasons", []),

            "recommendation": recommendation,

            "analysis_method": "local_heuristics_with_ssl_dns_cloudflare",

            "risk_diagnostics": {
                "url_structure_contribution": url_result.get("risk_contribution", 0),
                "malware_detected": malware_detected,
                "phishing_detected": phishing_detected,
                "domain_reputation": signals.get("domain_reputation", "UNKNOWN"),
                "ssl_status": signals.get("ssl_status", "NOT_CHECKED"),
                "risk_engine_ssl_status": result.get("ssl_status", "NOT_CHECKED"),
                "ssl_problem": result.get("ssl_problem", False),
                "safe_browsing_test_type": safe_browsing_test_type,
                "dns_status": dns_result.get("status", "UNKNOWN"),
                "strict_safe_browsing": (
                    safe_browsing_enabled and strict_mode_enabled
                ),
            },

            # Cloudflare
            "cloudflare": cloudflare_result,
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
