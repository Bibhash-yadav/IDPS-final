
from urllib.parse import urlsplit


BRAND_NAMES = {
    "google",
    "microsoft",
    "paypal",
    "amazon",
    "apple",
    "facebook",
    "instagram",
}


def detect_phishing(url: str) -> dict:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")

    findings = []
    score = 0

    if not hostname:
        return {
            "phishing_detected": False,
            "phishing_confidence": 0.0,
            "findings": ["Invalid hostname"],
            "analysis_method": "local_phishing_heuristics",
        }

    labels = hostname.split(".")
    registered_domain_candidate = (
        labels[-2] if len(labels) >= 2 else hostname
    )

    # A brand name in a hostname is a signal to review,
    # not proof that the domain is impersonating that brand.
    for brand in BRAND_NAMES:
        if brand in hostname and brand != registered_domain_candidate:
            if not hostname.endswith(f".{brand}.com"):
                findings.append(
                    f"Brand name '{brand}' appears in an unusual hostname"
                )
                score += 20
                break

    if "@" in parsed.netloc:
        findings.append("URL contains an @ symbol")
        score += 25

    if hostname.startswith("xn--") or ".xn--" in hostname:
        findings.append("Hostname contains punycode")
        score += 20

    suspicious_terms = (
        "signin",
        "verify",
        "password",
        "credential",
        "account-security",
    )

    matched_terms = [
        term for term in suspicious_terms if term in url.lower()
    ]

    if matched_terms:
        findings.append(
            "Credential-related terms appear in the URL"
        )
        score += min(20, len(matched_terms) * 5)

    score = min(score, 100)

    return {
        "phishing_detected": score >= 40,
        "phishing_confidence": round(score / 100, 2),
        "findings": findings,
        "risk_contribution": score,
        "analysis_method": "local_phishing_heuristics",
    }
