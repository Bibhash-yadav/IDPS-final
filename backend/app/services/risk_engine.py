
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

# Known adult-content domains.
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

# URL indicators, not proof by themselves.
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
    """Map a 0-100 score to a risk level."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _normalize_ssl_status(
    ssl_status: str | None,
    ssl_valid: bool | None,
) -> str:
    """Normalize SSL certificate status."""
    status = str(ssl_status or "").strip().upper()

    if status:
        return status

    if ssl_valid is True:
        return "VALID"

    if ssl_valid is False:
        return "INVALID"

    return "NOT_CHECKED"


SSL_BLOCKING_STATUSES = {
    "HOSTNAME_MISMATCH",
    "EXPIRED",
    "NOT_YET_VALID",
    "INVALID",
    "TLS_ERROR",
    "CERTIFICATE_REVOKED",
}

SSL_WARNING_STATUSES = {
    "TIMEOUT",
    "UNAVAILABLE",
    "ERROR",
    "NOT_CHECKED",
    "DNS_ERROR",
}


def _apply_ssl_risk(
    score: int,
    reasons: list[str],
    ssl_status: str,
) -> tuple[int, bool]:
    """Add SSL/TLS risk. Returns score and certificate problem."""
    if ssl_status == "VALID":
        return score, False

    if ssl_status in SSL_BLOCKING_STATUSES:
        reasons.append(
            f"SSL/TLS certificate verification failed: {ssl_status}."
        )
        return max(score, 60), True

    if ssl_status in SSL_WARNING_STATUSES:
        reasons.append(
            f"SSL/TLS certificate status could not be verified: {ssl_status}."
        )
        return max(score, 50), True

    if ssl_status in {"NOT_APPLICABLE", "HTTP_ONLY"}:
        reasons.append(
            "The URL does not use HTTPS; traffic is not protected by TLS."
        )
        return max(score, 30), True

    reasons.append(
        f"SSL/TLS status is unrecognized: {ssl_status}."
    )

    return max(score, 50), True


def _get_original_url(*results: dict[str, Any]) -> str:
    """Find the original URL in analyzer result dictionaries."""
    for result in results:
        if not isinstance(result, dict):
            continue

        for key in (
            "url",
            "original_url",
            "input_url",
            "target_url",
        ):
            value = result.get(key)

            if isinstance(value, str) and value.strip():
                return value.strip()

    return ""


def is_google_malware_test_url(url: str) -> bool:
    """Recognize the exact Google Safe Browsing malware test URL."""
    try:
        parsed = urlparse(str(url).strip())

        return (
            parsed.scheme.lower() == "https"
            and (parsed.hostname or "").lower()
            == GOOGLE_MALWARE_TEST_HOST
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
    Detect known adult domains and explicit URL indicators.

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

        for domain in ADULT_CONTENT_DOMAINS:
            domain = domain.lower().rstrip(".")

            if hostname == domain or hostname.endswith("." + domain):
                return True

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
    """Build a consistent adult-content block response."""
    if user_age is None:
        reason = (
            "Adult content is blocked because the user's age "
            "has not been verified."
        )
        age_status = "AGE_NOT_VERIFIED"

    else:
        reason = (
            "Adult content is restricted to users aged 18 or older. "
            f"Entered age: {user_age}."
        )
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
        "age_decision": "BLOCK",
        "confirmed_threat": False,
        "ssl_valid": None,
        "ssl_status": "NOT_CHECKED",
        "ssl_error": None,
        "ssl_problem": False,
        "adult_content_detected": True,
        "blocklisted": False,
        "allowlisted": False,
        "detection_status": {
            "url_structure": "ADULT_CONTENT_RULE_MATCH",
            "malware": "NOT_ESTABLISHED",
            "phishing": "NOT_ESTABLISHED",
            "domain_reputation": "UNKNOWN",
            "https": "NOT_A_SAFETY_GUARANTEE",
            "ssl_tls": "NOT_CHECKED",
            "age_restriction": age_status,
            "domain_rule": "AGE_POLICY_BLOCK",
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
        "ssl_valid": None,
        "ssl_status": "NOT_CHECKED",
        "ssl_error": None,
        "ssl_problem": False,
        "adult_content_detected": False,
        "blocklisted": False,
        "allowlisted": False,
        "detection_status": {
            "url_structure": "TEST_CASE",
            "malware": "TEST_CASE_MATCH",
            "phishing": "NOT_TESTED",
            "domain_reputation": "UNKNOWN",
            "https": "ENABLED",
            "ssl_tls": "NOT_CHECKED",
            "age_restriction": "NOT_ESTABLISHED",
            "domain_rule": "THREAT_BLOCK",
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
    ssl_valid: bool | None = None,
    ssl_status: str | None = None,
    ssl_error: str | None = None,
) -> dict[str, Any]:
    """
    Calculate risk and enforce security policies.

    BLOCK rules take priority over ALLOW rules.
    ALLOW cannot bypass confirmed threats or age restrictions.
    A LOW score does not prove a site is safe.
    """
    url_result = (
        url_result if isinstance(url_result, dict) else {}
    )

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

    # Official malware test URL.
    if is_google_malware_test_url(original_url):
        return _google_malware_test_result(user_age)

    # Adult-content policy takes priority over allowlist.
    if is_adult_content_url(original_url):
        if user_age is None or user_age < 18:
            return _adult_content_block_result(user_age)

    score = _safe_score(
        url_result.get("risk_contribution")
    )

    reasons: list[str] = []

    normalized_ssl_status = _normalize_ssl_status(
        ssl_status,
        ssl_valid,
    )

    score, ssl_problem = _apply_ssl_risk(
        score,
        reasons,
        normalized_ssl_status,
    )

    if ssl_error:
        reasons.append(
            f"SSL/TLS verification detail: {str(ssl_error)[:300]}"
        )

    # Calculate this BEFORE using it in decision logic.
    url_score = _safe_score(
        url_result.get("risk_contribution")
    )

    # 1. URL structure findings.
    findings = url_result.get("findings", [])

    if isinstance(findings, list):
        reasons.extend(
            str(item) for item in findings if item
        )

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

        phishing_findings = phishing_result.get(
            "findings",
            [],
        )

        if isinstance(phishing_findings, list):
            reasons.extend(
                str(item)
                for item in phishing_findings
                if item
            )

        if not phishing_findings:
            reasons.append(
                "URL triggered a configured phishing rule."
            )

    # 4. Domain reputation.
    reputation = str(
        domain_reputation or "UNKNOWN"
    ).strip().upper()

    if reputation not in VALID_REPUTATIONS:
        reputation = "UNKNOWN"

        reasons.append(
            "Reputation response was unrecognized; "
            "reputation is unverified."
        )

    if reputation == "MALICIOUS":
        score += 40

        reasons.append(
            "Domain reputation is marked malicious."
        )

    elif reputation == "SUSPICIOUS":
        score += 20

        reasons.append(
            "Domain reputation is marked suspicious."
        )

    elif reputation == "UNKNOWN":
        reasons.append(
            "External domain reputation has not been verified; "
            "this alone is not evidence of a threat."
        )

    # 5. Age policy.
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

    # 6. Explicit domain policies.
    if is_blocklisted:
        reasons.append(
            "Domain matches a configured blocklist rule."
        )

    if is_allowlisted:
        reasons.append(
            "Domain matches an allowlist rule."
        )

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
        and (
            malware_detected
            or phishing_detected
            or url_score > 0
            or ssl_problem
        )
    ):
        decision = "WARN"

    else:
        decision = "ALLOW"

    # 9. Allowlist policy.
    # This is also enforced in apply_domain_rules().
    if (
        is_allowlisted
        and not confirmed_threat
        and not is_blocklisted
        and not age_block
        and risk_level not in {"HIGH", "CRITICAL"}
    ):
        decision = "ALLOW"

    # 10. Detection statuses.
    https_enabled = bool(
        url_result.get("https_enabled", False)
    )

    detection_status = {
        "url_structure": (
            "SUSPICIOUS"
            if url_score > 0
            else "NO_INDICATORS_FOUND"
        ),
        "malware": (
            "DETECTED"
            if malware_detected
            else "NO_LOCAL_LIST_MATCH"
        ),
        "phishing": (
            "DETECTED"
            if phishing_detected
            else "NO_LOCAL_RULE_TRIGGERED"
        ),
        "domain_reputation": reputation,
        "https": (
            "ENABLED"
            if https_enabled
            else "NOT_ENABLED"
        ),
        "ssl_tls": normalized_ssl_status,
        "age_restriction": (
            "BLOCK"
            if age_block
            else "NOT_ESTABLISHED"
            if not age_restricted or required_age is None
            else "NO_BLOCK"
        ),
    }

    # 11. Explain final decision.
    if decision == "BLOCK":
        reasons.append(
            "The configured security policy blocks this URL."
        )

    elif decision == "WARN":
        reasons.append(
            "The URL has risk indicators that warrant caution."
        )

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
        "age_decision": (
            "BLOCK" if age_block else "ALLOW"
        ),
        "confirmed_threat": confirmed_threat,
        "ssl_valid": ssl_valid,
        "ssl_status": normalized_ssl_status,
        "ssl_error": (
            str(ssl_error)[:300] if ssl_error else None
        ),
        "ssl_problem": ssl_problem,
        "adult_content_detected": False,
        "blocklisted": bool(is_blocklisted),
        "allowlisted": bool(is_allowlisted),
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

    example.com matches:
        example.com
        shop.example.com

    It does not match:
        notexample.com
        example.com.attacker.net
    """
    host = (
        (hostname or "")
        .strip()
        .lower()
        .rstrip(".")
    )

    rule = (
        (rule_domain or "")
        .strip()
        .lower()
        .rstrip(".")
    )

    if not host or not rule:
        return False

    return (
        host == rule
        or host.endswith("." + rule)
    )


def apply_domain_rules(
    result: dict[str, Any],
    hostname: str,
    rules: list[Any],
) -> dict[str, Any]:
    """
    Apply the logged-in user's saved domain rules.

    Priority:
    1. BLOCK rule always wins.
    2. Confirmed malware/phishing threats cannot be bypassed.
    3. Adult-content and age-policy blocks cannot be bypassed.
    4. ALLOW can override LOW or MEDIUM risk decisions.
    5. ALLOW cannot override HIGH or CRITICAL risk.
    """
    updated_result = result.copy()

    matching_blocks = []
    matching_allows = []

    # Find matching rules.
    for rule in rules or []:
        rule_type = str(
            getattr(rule, "rule_type", "")
        ).strip().upper()

        rule_domain = str(
            getattr(rule, "domain", "")
        ).strip()

        if not domain_matches_rule(
            hostname,
            rule_domain,
        ):
            continue

        if rule_type == "BLOCK":
            matching_blocks.append(rule)

        elif rule_type == "ALLOW":
            matching_allows.append(rule)

    # Default states.
    updated_result["blocklisted"] = False
    updated_result["allowlisted"] = False

    # BLOCK always takes priority.
    if matching_blocks:
        matched_domain = str(
            matching_blocks[0].domain
        )

        updated_result["decision"] = "BLOCK"

        updated_result["risk_level"] = "CRITICAL"

        updated_result["risk_score"] = max(
            _safe_score(
                updated_result.get("risk_score")
            ),
            80,
        )

        updated_result["blocklisted"] = True
        updated_result["allowlisted"] = False

        reasons = updated_result.get("reasons") or []

        if isinstance(reasons, str):
            reasons = [reasons]

        reasons.append(
            f"Blocked by your saved domain rule: {matched_domain}."
        )

        if matching_allows:
            reasons.append(
                "A matching ALLOW rule was ignored because BLOCK rules "
                "have higher priority."
            )

        updated_result["reasons"] = list(
            dict.fromkeys(reasons)
        )

        updated_result["detection_status"] = {
            **updated_result.get("detection_status", {}),
            "domain_rule": "BLOCK",
        }

        return updated_result

    # No matching BLOCK rule.
    # Check matching ALLOW rules.
    if matching_allows:
        matched_domain = str(
            matching_allows[0].domain
        )

        updated_result["allowlisted"] = True

        # Never bypass confirmed threats.
        confirmed_threat = bool(
            updated_result.get("confirmed_threat", False)
            or updated_result.get("malware_detected", False)
            or updated_result.get("phishing_detected", False)
            or str(
                updated_result.get("domain_reputation", "")
            ).upper() == "MALICIOUS"
        )

        # Never bypass age restrictions.
        age_block = (
            str(
                updated_result.get("age_decision", "")
            ).upper() == "BLOCK"
        )

        # Never bypass adult-content blocks.
        adult_block = bool(
            updated_result.get("adult_content_detected", False)
        )

        # Never bypass high or critical risk.
        current_score = _safe_score(
            updated_result.get("risk_score")
        )

        current_risk_level = str(
            updated_result.get("risk_level", "")
        ).upper()

        high_risk = (
            current_risk_level in {"HIGH", "CRITICAL"}
            or current_score >= 60
        )

        if (
            not confirmed_threat
            and not age_block
            and not adult_block
            and not high_risk
        ):
            updated_result["decision"] = "ALLOW"

            reasons = updated_result.get("reasons") or []

            if isinstance(reasons, str):
                reasons = [reasons]

            reasons.append(
                f"Allowed by your saved domain rule: {matched_domain}."
            )

            updated_result["reasons"] = list(
                dict.fromkeys(reasons)
            )

            updated_result["detection_status"] = {
                **updated_result.get("detection_status", {}),
                "domain_rule": "ALLOW",
            }

        else:
            reasons = updated_result.get("reasons") or []

            if isinstance(reasons, str):
                reasons = [reasons]

            reasons.append(
                "Your ALLOW rule was not applied because a higher-priority "
                "security policy or risk condition blocks this URL."
            )

            updated_result["reasons"] = list(
                dict.fromkeys(reasons)
            )

            updated_result["detection_status"] = {
                **updated_result.get("detection_status", {}),
                "domain_rule": "ALLOW_OVERRIDDEN_BY_SECURITY",
            }

    else:
        updated_result["blocklisted"] = False
        updated_result["allowlisted"] = False

        updated_result["detection_status"] = {
            **updated_result.get("detection_status", {}),
            "domain_rule": "NO_CUSTOM_RULE_MATCH",
        }

    return updated_result
