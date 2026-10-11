
from typing import Any


RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
VALID_REPUTATIONS = {"UNKNOWN", "SAFE", "TRUSTED", "SUSPICIOUS", "MALICIOUS"}


def _safe_score(value: Any) -> int:
    """Convert a score to a non-negative integer safely."""
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _risk_level(score: int) -> str:
    """Map a 0–100 heuristic score to a risk level."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


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
    Calculate heuristic risk and a security decision.

    A LOW score does not prove that a site is safe.
    HTTPS protects the connection but does not prove site legitimacy.
    Unknown reputation alone does not cause a warning.
    """

    url_result = url_result if isinstance(url_result, dict) else {}
    malware_result = malware_result if isinstance(malware_result, dict) else {}
    phishing_result = phishing_result if isinstance(phishing_result, dict) else {}

    score = _safe_score(url_result.get("risk_contribution"))
    reasons: list[str] = []

    # 1. URL structure findings
    findings = url_result.get("findings", [])
    if isinstance(findings, list):
        reasons.extend(
            str(item) for item in findings if item
        )

    # 2. Malware detector
    malware_detected = bool(
        malware_result.get("malware_detected", False)
    )

    if malware_detected:
        score += 50
        reasons.append("URL matched the configured malware detection list.")

    # 3. Phishing detector
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

    # 4. Reputation
    reputation = str(
        domain_reputation or "UNKNOWN"
    ).strip().upper()

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

    # 5. Age policy
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

    # 6. Explicit domain policy
    if is_blocklisted:
        reasons.append("Domain matches a configured blocklist rule.")

    if is_allowlisted:
        reasons.append("Domain matches an allowlist rule.")

    # 7. Confirmed threat status
    confirmed_threat = (
        malware_detected
        or phishing_detected
        or reputation == "MALICIOUS"
    )

    # Clamp after combining all signals.
    score = min(score, 100)
    risk_level = _risk_level(score)

    # 8. Decision priority
    # Threats, explicit blocks, and age restrictions take precedence.
    if confirmed_threat or is_blocklisted or age_block:
        decision = "BLOCK"
    elif risk_level in {"HIGH", "CRITICAL"}:
        decision = "BLOCK"
    elif risk_level == "MEDIUM":
        decision = "WARN"
    elif strict_safe_browsing and score > 0 and reputation == "UNKNOWN":
        decision = "WARN"
    else:
        # LOW score with no blocking indicators: allow.
        # Unknown reputation alone does not force WARN.
        decision = "ALLOW"

    # 9. Allowlist may bypass ordinary warnings only.
    # It must not bypass confirmed threats, blocklists, age blocks,
    # or high/critical risk.
    if (
        is_allowlisted
        and not confirmed_threat
        and not is_blocklisted
        and not age_block
        and risk_level not in {"HIGH", "CRITICAL"}
    ):
        decision = "ALLOW"

    # 10. UI detection statuses
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
            "BLOCK" if age_block
            else "NOT_ESTABLISHED" if not age_restricted or required_age is None
            else "NO_BLOCK"
        ),
    }

    # Add a summary that explains the final decision.
    if decision == "BLOCK":
        reasons.append("The configured security policy blocks this URL.")
    elif decision == "WARN":
        reasons.append(
            "The URL has risk indicators that warrant caution."
        )
    elif decision == "ALLOW":
        reasons.append(
            "No configured blocking indicators were found. "
            "This does not guarantee that the website is safe."
        )

    return {
        "risk_score": score,
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
        "detection_status": detection_status,
        "analysis_method": "rule_based_risk_engine",
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
    Apply the user's saved domain rules.

    A matching BLOCK rule forces a block. ALLOW rules do not reduce
    risk or override confirmed threats.
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

        # Keep the UI summary consistent with the final policy decision.
        updated_result["detection_status"] = {
            **updated_result.get("detection_status", {}),
            "domain_rule": "BLOCK",
        }

    else:
        updated_result.setdefault("blocklisted", False)

    return updated_result
