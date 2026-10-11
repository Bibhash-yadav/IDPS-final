
from typing import Any
from urllib.parse import urlparse, unquote


RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

VALID_REPUTATIONS = {
    "UNKNOWN",
    "SAFE",
    "TRUSTED",
    "SUSPICIOUS",
    "MALICIOUS",
}

GOOGLE_MALWARE_TEST_HOST = "testsafebrowsing.appspot.com"
GOOGLE_MALWARE_TEST_PATH = "/apiv4/ANY_PLATFORM/MALWARE/URL"

# Known adult-content domains. Add or remove domains to match your policy.
ADULT_CONTENT_DOMAINS = {
    "pornhub.com",
    "xvideos.com",
    "xnxx.com",
    "xhamster.com",
    "xhaccess.com",
    "redtube.com",
    "youporn.com",
    "tube8.com",
    "spankbang.com",
    "tnaflix.com",
    "motherless.com",
    "eporner.com",
    "beeg.com",
    "rule34.xxx",
    "chaturbate.com",
    "stripchat.com",
    "livejasmin.com",
    "brazzers.com",
    "bangbros.com",
    "adulttime.com",
    "hentaihaven.xxx",
}

# URL indicators, not proof by themselves that a site contains adult content.
ADULT_URL_KEYWORDS = (
    "porn",
    "xxx",
    "hentai",
    "nsfw",
    "adult-video",
    "adultvideo",
    "sex-video",
    "sexvideo",
    "x-rated",
    "explicit-content",
)


def _safe_score(value: Any) -> int:
    """Convert a score to an integer between 0 and 100 safely."""
    try:
        return min(100, max(0, int(value or 0)))
    except (TypeError, ValueError, OverflowError):
        return 0


def _risk_level(score: int) -> str:
    """Map a 0–100 score to a risk level."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _get_original_url(*results: dict[str, Any]) -> str:
    """Find the original URL in analyzer result dictionaries."""
    for result in results:
        if not isinstance(result, dict):
            continue

        for key in ("url", "original_url", "input_url", "target_url"):
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    return ""


def is_google_malware_test_url(url: str) -> bool:
    """Recognize only the exact Google Safe Browsing malware test URL."""
    try:
        parsed = urlparse(str(url).strip())
        return (
            parsed.scheme.lower() == "https"
            and (parsed.hostname or "").lower() == GOOGLE_MALWARE_TEST_HOST
            and parsed.path.rstrip("/") == GOOGLE_MALWARE_TEST_PATH
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        )
    except (TypeError, ValueError):
        return False


def is_adult_content_url(url: str) -> bool:
    """
    Detect known adult domains and explicit adult-content URL indicators.

    This is a rule-based filter, not a complete content classifier.
    """
    if not isinstance(url, str) or not url.strip():
        return False

    try:
        candidate = url.strip()
        parsed = urlparse(
            candidate if "://" in candidate else f"https://{candidate}"
        )

        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            return False

        # Match a known adult domain and its subdomains.
        for domain in ADULT_CONTENT_DOMAINS:
            domain = domain.lower().rstrip(".")
            if hostname == domain or hostname.endswith("." + domain):
                return True

        # Check the URL components for explicit category indicators.
        searchable_url = unquote(
            f"{hostname}{parsed.path} {parsed.query}"
        ).lower()

        return any(
            keyword in searchable_url
            for keyword in ADULT_URL_KEYWORDS
        )

    except (TypeError, ValueError):
        return False


def _adult_content_block_result(
    user_age: int | None,
) -> dict[str, Any]:
    """Build a consistent block response for adult content."""
    if user_age is None:
        reason = (
            "Adult content is blocked because the user's age "
            "has not been verified."
        )
        age_decision = "BLOCK"
        age_status = "AGE_NOT_VERIFIED"
    else:
        reason = (
            f"Adult content is restricted to users aged 18 or older. "
            f"Entered age: {user_age}."
        )
        age_decision = "BLOCK"
        age_status = "BLOCK_UNDER_18"

    return {
        "risk_score": 100,
        "risk_level": "CRITICAL",
        "decision": "BLOCK",
        "reasons": [
            "The URL matches an adult-content domain or URL rule.",
            reason,
        ],
        "malware_detected": False,
        "phishing_detected": False,
        "domain_reputation": "UNKNOWN",
        "age_restricted": True,
        "required_age": 18,
        "user_age": user_age,
        "age_decision": age_decision,
        "confirmed_threat": False,
        "adult_content_detected": True,
        "detection_status": {
            "url_structure": "ADULT_CONTENT_RULE_MATCH",
            "malware": "NOT_ESTABLISHED",
            "phishing": "NOT_ESTABLISHED",
            "domain_reputation": "UNKNOWN",
            "https": "NOT_A_SAFETY_GUARANTEE",
            "ssl_tls": "NOT_CHECKED",
            "age_restriction": age_status,
        },
        "analysis_method": "adult_content_age_policy",
        "test_mode": False,
    }


def _google_malware_test_result(
    user_age: int | None,
) -> dict[str, Any]:
    """Return an explicit result for the official malware test endpoint."""
    return {
        "risk_score": 85,
        "risk_level": "HIGH",
        "decision": "BLOCK",
        "reasons": [
            "Recognized the Google Safe Browsing malware test URL.",
            "This is a test-case classification, not proof of a real infection.",
        ],
        "malware_detected": True,
        "phishing_detected": False,
        "domain_reputation": "UNKNOWN",
        "age_restricted": False,
        "required_age": None,
        "user_age": user_age,
        "age_decision": "ALLOW",
        "confirmed_threat": True,
        "adult_content_detected": False,
        "detection_status": {
            "url_structure": "TEST_CASE",
            "malware": "TEST_CASE_MATCH",
            "phishing": "NOT_TESTED",
            "domain_reputation": "UNKNOWN",
            "https": "ENABLED",
            "ssl_tls": "NOT_CHECKED",
            "age_restriction": "NOT_ESTABLISHED",
        },
        "analysis_method": "safe_browsing_test_case",
        "test_mode": True,
    }


def calculate_risk(
    url_result: dict[str, Any],
    malware_result: dict[str, Any],
    phishing_result: dict[str, Any],
    domain_reputation: str = "UNKNOWN",
    is_blocklisted: bool = False,
    is_allowlisted: bool = False,
    age_restricted: bool = False,
    required_age: int | None = None,
    user_age: int | None = None,
    strict_safe_browsing: bool = False,
) -> dict[str, Any]:
    """
    Calculate risk and enforce adult-content age restrictions.

    Adult-content rules take priority over allowlist rules.
    A LOW score does not prove that a site is safe.
    HTTPS does not prove that a website is legitimate.
    """
    url_result = url_result if isinstance(url_result, dict) else {}
    malware_result = (
        malware_result if isinstance(malware_result, dict) else {}
    )
    phishing_result = (
        phishing_result if isinstance(phishing_result, dict) else {}
    )

    original_url = _get_original_url(
        url_result,
        malware_result,
        phishing_result,
    )

    # Explicit malware test-case override.
    if is_google_malware_test_url(original_url):
        return _google_malware_test_result(user_age)

    # Enforce the adult-content policy before normal risk/allowlist logic.
    # Missing age is treated as unverified and blocked for known adult URLs.
    if is_adult_content_url(original_url):
        if user_age is None or user_age < 18:
            return _adult_content_block_result(user_age)

    score = _safe_score(url_result.get("risk_contribution"))
    reasons: list[str] = []

    # 1. URL structure findings.
    findings = url_result.get("findings", [])
    if isinstance(findings, list):
        reasons.extend(str(item) for item in findings if item)

    # 2. Malware detector.
    malware_detected = bool(
        malware_result.get("malware_detected", False)
    )
    if malware_detected:
        score += 50
        reasons.append(
            "URL matched the configured malware detection list."
        )

    # 3. Phishing detector.
    phishing_detected = bool(
        phishing_result.get("phishing_detected", False)
    )
    if phishing_detected:
        score += 40
        phishing_findings = phishing_result.get("findings", [])
        if isinstance(phishing_findings, list):
            reasons.extend(
                str(item) for item in phishing_findings if item
            )
        if not phishing_findings:
            reasons.append("URL triggered a configured phishing rule.")

    # 4. Domain reputation.
    reputation = str(domain_reputation or "UNKNOWN").strip().upper()
    if reputation not in VALID_REPUTATIONS:
        reputation = "UNKNOWN"
        reasons.append(
            "Reputation response was unrecognized; reputation is unverified."
        )

    if reputation == "MALICIOUS":
        score += 40
        reasons.append("Domain reputation is marked malicious.")
    elif reputation == "SUSPICIOUS":
        score += 20
        reasons.append("Domain reputation is marked suspicious.")
    elif reputation == "UNKNOWN":
        reasons.append(
            "External domain reputation has not been verified; "
            "this alone is not evidence of a threat."
        )

    # 5. Age policy passed by the caller.
    age_block = (
        bool(age_restricted)
        and required_age is not None
        and user_age is not None
        and user_age < required_age
    )

    if age_restricted and required_age is None:
        reasons.append(
            "An age restriction was reported, but its minimum age is unknown."
        )

    if age_restricted and user_age is None:
        reasons.append("User age was not provided.")

    if age_block:
        reasons.append(
            f"Age policy requires {required_age}+; "
            f"entered age is {user_age}."
        )

    # 6. Explicit domain policy.
    if is_blocklisted:
        reasons.append("Domain matches a configured blocklist rule.")

    if is_allowlisted:
        reasons.append("Domain matches an allowlist rule.")

    # 7. Confirmed threat status.
    confirmed_threat = (
        malware_detected
        or phishing_detected
        or reputation == "MALICIOUS"
    )

    score = min(score, 100)
    risk_level = _risk_level(score)

    # 8. Decision priority.
    if confirmed_threat or is_blocklisted or age_block:
        decision = "BLOCK"
    elif risk_level in {"HIGH", "CRITICAL"}:
        decision = "BLOCK"
    elif risk_level == "MEDIUM":
        decision = "WARN"
    elif (
        strict_safe_browsing
        and score > 0
        and reputation == "UNKNOWN"
    ):
        decision = "WARN"
    else:
        decision = "ALLOW"

    # 9. Allowlist cannot override confirmed threats or policy blocks.
    if (
        is_allowlisted
        and not confirmed_threat
        and not is_blocklisted
        and not age_block
        and risk_level not in {"HIGH", "CRITICAL"}
    ):
        decision = "ALLOW"

    # 10. Detection statuses.
    url_score = _safe_score(url_result.get("risk_contribution"))
    https_enabled = bool(url_result.get("https_enabled", False))

    detection_status = {
        "url_structure": (
            "SUSPICIOUS" if url_score > 0 else "NO_INDICATORS_FOUND"
        ),
        "malware": (
            "DETECTED" if malware_detected else "NO_LOCAL_LIST_MATCH"
        ),
        "phishing": (
            "DETECTED" if phishing_detected else "NO_LOCAL_RULE_TRIGGERED"
        ),
        "domain_reputation": reputation,
        "https": "ENABLED" if https_enabled else "NOT_ENABLED",
        "ssl_tls": "NOT_CHECKED",
        "age_restriction": (
            "BLOCK"
            if age_block
            else "NOT_ESTABLISHED"
            if not age_restricted or required_age is None
            else "NO_BLOCK"
        ),
    }

    # 11. Explain the final decision.
    if decision == "BLOCK":
        reasons.append("The configured security policy blocks this URL.")
    elif decision == "WARN":
        reasons.append("The URL has risk indicators that warrant caution.")
    else:
        reasons.append(
            "No configured blocking indicators were found. "
            "This does not guarantee that the website is safe."
        )

    return {
        "risk_score": min(score, 100),
        "risk_level": risk_level,
        "decision": decision,
        "reasons": list(dict.fromkeys(reasons)),
        "malware_detected": malware_detected,
        "phishing_detected": phishing_detected,
        "domain_reputation": reputation,
        "age_restricted": bool(age_restricted),
        "required_age": required_age,
        "user_age": user_age,
        "age_decision": "BLOCK" if age_block else "ALLOW",
        "confirmed_threat": confirmed_threat,
        "adult_content_detected": False,
        "detection_status": detection_status,
        "analysis_method": "rule_based_risk_engine",
        "test_mode": False,
    }


def domain_matches_rule(
    hostname: str,
    rule_domain: str,
) -> bool:
    """
    Match a domain and its subdomains without matching lookalikes.

    example.com matches example.com and shop.example.com.
    notexample.com does not match example.com.
    """
    host = (hostname or "").strip().lower().rstrip(".")
    rule = (rule_domain or "").strip().lower().rstrip(".")

    if not host or not rule:
        return False

    return host == rule or host.endswith("." + rule)


def apply_domain_rules(
    result: dict[str, Any],
    hostname: str,
    rules: list[Any],
) -> dict[str, Any]:
    """
    Apply saved domain rules.

    A matching BLOCK rule forces a block. ALLOW rules do not reduce
    risk or override confirmed threats or age-policy blocks.
    """
    updated_result = result.copy()

    matching_blocks = [
        rule
        for rule in rules
        if str(getattr(rule, "rule_type", "")).strip().upper() == "BLOCK"
        and domain_matches_rule(
            hostname,
            str(getattr(rule, "domain", "")),
        )
    ]

    if matching_blocks:
        matched_domain = str(matching_blocks[0].domain)
        updated_result["decision"] = "BLOCK"
        updated_result["risk_level"] = "CRITICAL"
        updated_result["risk_score"] = max(
            _safe_score(updated_result.get("risk_score")),
            80,
        )
        updated_result["blocklisted"] = True

        reasons = list(updated_result.get("reasons") or [])
        reasons.append(
            f"Blocked by your saved domain rule: {matched_domain}."
        )
        updated_result["reasons"] = list(dict.fromkeys(reasons))

        updated_result["detection_status"] = {
            **updated_result.get("detection_status", {}),
            "domain_rule": "BLOCK",
        }
    else:
        updated_result.setdefault("blocklisted", False)

    return updated_result
