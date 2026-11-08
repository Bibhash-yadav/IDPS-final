
import asyncio
import logging
import os
from typing import Any
from urllib.parse import urlsplit

from dotenv import load_dotenv

from app.services.urlhaus import check_urlhaus
from app.services.threatfox import check_threatfox
from app.services.openphish import check_openphish
from app.services.cloudflare_service import CloudflareService


# =========================================================
# CONFIGURATION
# =========================================================

load_dotenv()

logger = logging.getLogger(__name__)

THREAT_INTEL_ENABLED = (
    os.getenv("THREAT_INTEL_ENABLED", "true").lower() == "true"
)

THREAT_INTEL_TIMEOUT = float(
    os.getenv("THREAT_INTEL_TIMEOUT", "10")
)

CLOUDFLARE_TOTAL_TIMEOUT = float(
    os.getenv("CLOUDFLARE_TOTAL_TIMEOUT", "45")
)


# =========================================================
# URL VALIDATION
# =========================================================

def normalize_url(url: str) -> str:
    """Validate and normalize an HTTP or HTTPS URL."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty.")

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlsplit(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.hostname:
            raise ValueError("Invalid URL or domain.")

        if parsed.username or parsed.password:
            raise ValueError(
                "URLs containing credentials are not allowed."
            )

        # Validate port syntax.
        _ = parsed.port

    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc

    return parsed.geturl()


def extract_domain(url: str) -> str:
    """Extract the hostname from a URL."""

    parsed = urlsplit(normalize_url(url))
    return parsed.hostname.lower()


# =========================================================
# SAFE SOURCE EXECUTION
# =========================================================

async def run_source(
    source_name: str,
    function,
    value: str,
) -> dict[str, Any]:
    """Run an intelligence provider safely with a timeout."""

    try:
        result = await asyncio.wait_for(
            function(value),
            timeout=THREAT_INTEL_TIMEOUT,
        )

        if not isinstance(result, dict):
            raise ValueError("Invalid source response.")

        result.setdefault("source", source_name)
        result.setdefault("status", "unavailable")
        result.setdefault("malicious", None)

        return result

    except asyncio.TimeoutError:
        logger.warning("%s request timed out.", source_name)

        return {
            "source": source_name,
            "status": "unavailable",
            "malicious": None,
            "message": "Request timed out.",
        }

    except Exception:
        logger.exception("%s request failed.", source_name)

        return {
            "source": source_name,
            "status": "unavailable",
            "malicious": None,
            "message": "Threat intelligence check failed.",
        }


# =========================================================
# CLOUDFLARE VERDICT EXTRACTION
# =========================================================

def extract_cloudflare_verdict(
    report: dict[str, Any],
) -> bool | None:
    """
    Extract an explicit Cloudflare overall verdict.

    True  = confirmed malicious
    False = explicit non-malicious verdict
    None  = no reliable verdict available

    IMPORTANT:
    malicious=False alone is NOT enough.
    Cloudflare must also return hasVerdicts=True.
    """

    if not isinstance(report, dict):
        return None

    verdicts = report.get("verdicts") or {}

    if not isinstance(verdicts, dict):
        return None

    overall = verdicts.get("overall") or {}

    if not isinstance(overall, dict):
        return None

    has_verdicts = overall.get("hasVerdicts")
    malicious = overall.get("malicious")

    # No explicit verdict means unknown, not clean.
    if has_verdicts is not True:
        return None

    if isinstance(malicious, bool):
        return malicious

    return None


# =========================================================
# CLOUDFLARE DOMAIN INTELLIGENCE
# =========================================================

async def fetch_cloudflare_domain_intelligence(
    cloudflare: CloudflareService,
    domain: str,
) -> dict[str, Any]:
    """Fetch Cloudflare domain intelligence independently."""

    try:
        result = await asyncio.wait_for(
            cloudflare.get_domain_intelligence(domain),
            timeout=THREAT_INTEL_TIMEOUT,
        )

        if isinstance(result, dict):
            return result

        return {
            "success": False,
            "message": "Invalid domain intelligence response.",
        }

    except asyncio.TimeoutError:
        logger.warning(
            "Cloudflare domain intelligence timed out."
        )

        return {
            "success": False,
            "message": "Domain intelligence request timed out.",
        }

    except Exception:
        logger.exception(
            "Cloudflare domain intelligence request failed."
        )

        return {
            "success": False,
            "message": "Domain intelligence unavailable.",
        }


# =========================================================
# CLOUDFLARE URL SCAN
# =========================================================

async def check_cloudflare(
    url: str,
    domain: str,
) -> dict[str, Any]:
    """
    Submit a URL to Cloudflare Scanner, wait for its report,
    and fetch domain intelligence.

    Pending and failed scans are never treated as clean.
    """

    cloudflare = None
    scan_id = None

    try:
        cloudflare = CloudflareService()

        # -------------------------------------------------
        # 1. Submit URL scan
        # -------------------------------------------------

        scan_submission = await asyncio.wait_for(
            cloudflare.scan_url(url),
            timeout=THREAT_INTEL_TIMEOUT,
        )

        if not isinstance(scan_submission, dict):
            raise ValueError(
                "Invalid Cloudflare scan submission response."
            )

        scan_id = scan_submission.get("scan_id")

        if not scan_id:
            return {
                "source": "Cloudflare",
                "status": "unavailable",
                "malicious": None,
                "message": (
                    scan_submission.get("message")
                    or "Cloudflare did not return a scan ID."
                ),
            }

        logger.info(
            "Cloudflare scan submitted. Scan ID: %s",
            scan_id,
        )

        # -------------------------------------------------
        # 2. Run scan polling and domain intelligence
        #    independently
        # -------------------------------------------------

        scan_task = cloudflare.wait_for_scan_result(
            scan_id=scan_id,
        )

        domain_task = fetch_cloudflare_domain_intelligence(
            cloudflare,
            domain,
        )

        try:
            scan_result, domain_intel = await asyncio.wait_for(
                asyncio.gather(
                    scan_task,
                    domain_task,
                ),
                timeout=CLOUDFLARE_TOTAL_TIMEOUT,
            )

        except asyncio.TimeoutError:
            logger.warning(
                "Cloudflare total scan timeout: %s",
                scan_id,
            )

            return {
                "source": "Cloudflare",
                "status": "pending",
                "malicious": None,
                "scan_id": scan_id,
                "domain_intelligence": {
                    "success": False,
                    "message": "Cloudflare scan timed out.",
                },
                "message": (
                    "Cloudflare scan is taking longer than expected. "
                    "No clean verdict has been assumed."
                ),
            }

        # -------------------------------------------------
        # 3. Validate scan response
        # -------------------------------------------------

        if not isinstance(scan_result, dict):
            raise ValueError(
                "Invalid Cloudflare scan result."
            )

        # -------------------------------------------------
        # 4. Handle scan still processing
        # -------------------------------------------------

        if scan_result.get("processing") is True:
            return {
                "source": "Cloudflare",
                "status": "pending",
                "malicious": None,
                "scan_id": scan_id,
                "domain_intelligence": domain_intel,
                "message": (
                    "Cloudflare scan is still processing. "
                    "No clean verdict has been assumed."
                ),
            }

        # -------------------------------------------------
        # 5. Handle unsuccessful API scan
        # -------------------------------------------------

        if scan_result.get("success") is not True:
            return {
                "source": "Cloudflare",
                "status": "unavailable",
                "malicious": None,
                "scan_id": scan_id,
                "domain_intelligence": domain_intel,
                "message": (
                    scan_result.get("message")
                    or "Cloudflare scan could not be completed."
                ),
            }

        # -------------------------------------------------
        # 6. Extract report
        # -------------------------------------------------

        report = scan_result.get("report") or {}

        if not isinstance(report, dict):
            report = {}

        # -------------------------------------------------
        # 7. Check Cloudflare task success
        # -------------------------------------------------

        task = report.get("task") or {}

        if isinstance(task, dict) and task.get("success") is False:
            errors = task.get("errors") or []

            error_messages = [
                error.get("message", "Unknown scan error")
                for error in errors
                if isinstance(error, dict)
            ]

            error_message = (
                "; ".join(error_messages)
                if error_messages
                else "Cloudflare reported an unsuccessful scan."
            )

            logger.warning(
                "Cloudflare scan did not complete. Scan ID: %s. Error: %s",
                scan_id,
                error_message,
            )

            return {
                "source": "Cloudflare",
                "status": "unavailable",
                "malicious": None,
                "scan_id": scan_id,
                "report": report,
                "domain_intelligence": domain_intel,
                "message": (
                    "Cloudflare did not complete the URL scan: "
                    + error_message
                ),
            }

        # -------------------------------------------------
        # 8. Extract explicit malicious verdict
        # -------------------------------------------------

        verdict = extract_cloudflare_verdict(report)

        if verdict is True:
            status = "found"
            malicious = True

            message = (
                "Cloudflare reported malicious indicators."
            )

        elif verdict is False:
            status = "not_found"
            malicious = False

            message = (
                "Cloudflare returned an explicit verdict "
                "with no malicious indicators."
            )

        else:
            status = "pending"
            malicious = None

            message = (
                "Cloudflare scan completed, but no explicit "
                "overall verdict is available. "
                "Manual review may be required."
            )

        # -------------------------------------------------
        # 9. Return Cloudflare result
        # -------------------------------------------------

        return {
            "source": "Cloudflare",
            "status": status,
            "malicious": malicious,
            "scan_id": scan_id,
            "report": report,
            "domain_intelligence": domain_intel,
            "message": message,
        }

    except asyncio.TimeoutError:
        logger.warning(
            "Cloudflare scan request timed out."
        )

        return {
            "source": "Cloudflare",
            "status": "unavailable",
            "malicious": None,
            "scan_id": scan_id,
            "message": "Cloudflare request timed out.",
        }

    except Exception:
        logger.exception("Cloudflare scan failed.")

        return {
            "source": "Cloudflare",
            "status": "unavailable",
            "malicious": None,
            "scan_id": scan_id,
            "message": (
                "Cloudflare scan could not be completed."
            ),
        }


# =========================================================
# THREAT SCORE CALCULATION
# =========================================================

def calculate_threat_score(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Calculate threat score using provider weights.

    Only confirmed malicious matches increase the score.
    Pending and unavailable sources are not treated as clean.
    """

    weights = {
        "URLhaus": 40,
        "ThreatFox": 35,
        "OpenPhish": 40,
        "Cloudflare": 35,
    }

    score = 0

    matched_sources = []
    checked_sources = []
    unavailable_sources = []
    pending_sources = []

    for result in results:
        source = result.get("source", "Unknown")
        status = result.get("status")
        malicious = result.get("malicious")

        # Confirmed malicious match.
        if status == "found" and malicious is True:
            matched_sources.append(source)
            score += weights.get(source, 0)

        # Confirmed clean lookup.
        elif status == "not_found" and malicious is False:
            checked_sources.append(source)

        # Provider could not be contacted or scan failed.
        elif status == "unavailable":
            unavailable_sources.append(source)

        # Still processing or no explicit verdict.
        else:
            pending_sources.append(source)

    score = min(score, 100)

    # -----------------------------------------------------
    # Risk classification
    # -----------------------------------------------------

    if score >= 80:
        risk_level = "CRITICAL"
        decision = "BLOCK"

    elif score >= 60:
        risk_level = "HIGH"
        decision = "BLOCK"

    elif score >= 30:
        risk_level = "MEDIUM"
        decision = "WARN"

    elif unavailable_sources or pending_sources:
        risk_level = "UNKNOWN"
        decision = "REVIEW"

    elif not checked_sources:
        risk_level = "UNKNOWN"
        decision = "REVIEW"

    else:
        risk_level = "LOW"
        decision = "ALLOW"

    return {
        "threat_score": score,
        "risk_level": risk_level,
        "decision": decision,
        "matched_sources": matched_sources,
        "checked_sources": checked_sources,
        "unavailable_sources": unavailable_sources,
        "pending_sources": pending_sources,
    }


# =========================================================
# MAIN THREAT ANALYSIS
# =========================================================

async def analyze_threat(
    url: str,
) -> dict[str, Any]:
    """
    Analyze a URL using:

    1. URLhaus
    2. ThreatFox
    3. OpenPhish
    4. Cloudflare URL Scanner
    5. Cloudflare Domain Intelligence
    """

    # -----------------------------------------------------
    # 1. Validate URL
    # -----------------------------------------------------

    try:
        complete_url = normalize_url(url)
        domain = extract_domain(complete_url)

    except ValueError as exc:
        return {
            "success": False,
            "url": url,
            "error": str(exc),
        }

    # -----------------------------------------------------
    # 2. Check configuration
    # -----------------------------------------------------

    if not THREAT_INTEL_ENABLED:
        return {
            "success": False,
            "url": complete_url,
            "error": "Threat intelligence is disabled.",
        }

    # -----------------------------------------------------
    # 3. Run all providers concurrently
    # -----------------------------------------------------

    tasks = [
        run_source(
            "URLhaus",
            check_urlhaus,
            complete_url,
        ),

        run_source(
            "ThreatFox",
            check_threatfox,
            domain,
        ),

        run_source(
            "OpenPhish",
            check_openphish,
            complete_url,
        ),

        check_cloudflare(
            complete_url,
            domain,
        ),
    ]

    source_results = await asyncio.gather(*tasks)

    # -----------------------------------------------------
    # 4. Calculate threat score
    # -----------------------------------------------------

    score_result = calculate_threat_score(
        source_results
    )

    threat_detected = bool(
        score_result["matched_sources"]
    )

    # -----------------------------------------------------
    # 5. Generate response message
    # -----------------------------------------------------

    if score_result["risk_level"] in ("CRITICAL", "HIGH"):
        message = (
            "High-confidence threat indicators were detected. "
            "Blocking is recommended."
        )

    elif score_result["risk_level"] == "MEDIUM":
        message = (
            "Suspicious threat indicators were detected. "
            "Further inspection is recommended."
        )

    elif score_result["risk_level"] == "UNKNOWN":
        message = (
            "Threat analysis is incomplete. "
            "Some sources are pending or unavailable. "
            "Manual review is recommended."
        )

    else:
        message = (
            "No matching threat indicators were found "
            "in the successfully checked sources."
        )

    # -----------------------------------------------------
    # 6. Final API response
    # -----------------------------------------------------

    return {
        "success": True,
        "url": complete_url,
        "domain": domain,

        "threat_detected": threat_detected,

        "threat_score": score_result["threat_score"],
        "risk_level": score_result["risk_level"],
        "decision": score_result["decision"],

        "matched_sources": score_result["matched_sources"],
        "checked_sources": score_result["checked_sources"],
        "unavailable_sources": score_result["unavailable_sources"],
        "pending_sources": score_result["pending_sources"],

        "total_sources": len(source_results),

        "source_results": source_results,

        "message": message,
    }
