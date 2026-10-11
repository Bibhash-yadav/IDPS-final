
import ipaddress
import re
from urllib.parse import urlsplit, unquote


SUSPICIOUS_KEYWORDS = {
    "login-verify",
    "account-suspended",
    "password-reset",
    "verify-account",
    "secure-update",
    "free-gift",
    "wallet-connect",
    "crypto-claim",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
}


def normalize_url(url: str) -> str:
    """Normalize a URL and add HTTPS when the scheme is missing."""
    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    return url


def analyze_url(url: str) -> dict:
    """
    Analyze URL structure using local heuristics.

    This function does not prove that a website is malicious.
    """
    normalized = normalize_url(url)

    try:
        parsed = urlsplit(normalized)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported")

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("URL must contain a valid hostname")

        hostname = hostname.rstrip(".").lower()
        decoded_url = unquote(normalized).lower()

    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc

    findings = []
    score = 0

    # URLs that use IP addresses instead of domain names
    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
        findings.append("URL uses an IP address instead of a domain")
        score += 20
    except ValueError:
        pass

    # URLs with excessively long paths or query strings
    if len(normalized) > 200:
        findings.append("URL is unusually long")
        score += 10

    # Many subdomains can hide the actual registered domain
    subdomain_count = max(0, len(hostname.split(".")) - 2)

    if subdomain_count >= 4:
        findings.append("URL contains many subdomains")
        score += 15

    # Embedded user information can disguise the destination
    if "@" in parsed.netloc:
        findings.append("URL contains an @ symbol in its authority")
        score += 25

    # Punycode can be legitimate but may also disguise lookalike domains
    if "xn--" in hostname:
        findings.append("Domain contains punycode")
        score += 20

    # Common URL shorteners conceal the final destination
    if hostname in URL_SHORTENERS:
        findings.append("URL uses a known URL shortening service")
        score += 15

    # Suspicious keywords are signals, not proof of phishing
    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in decoded_url
    ]

    if matched_keywords:
        findings.append(
            "URL contains suspicious keywords: "
            + ", ".join(matched_keywords)
        )
        score += min(20, len(matched_keywords) * 10)

    # Excessive query parameters
    if len(parsed.query.split("&")) >= 10:
        findings.append("URL contains many query parameters")
        score += 10

    # HTTP does not provide transport encryption
    https_enabled = parsed.scheme.lower() == "https"

    if not https_enabled:
        findings.append("Website uses HTTP instead of HTTPS")
        score += 10

    # Some TLDs have legitimate uses, so this is only a weak signal
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""

    if tld in SUSPICIOUS_TLDS:
        findings.append(f"Domain uses the .{tld} top-level domain")
        score += 5

    score = min(score, 100)

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "original_url": url,
        "normalized_url": normalized,
        "domain": hostname,
        "https_enabled": https_enabled,
        "is_ip_address": is_ip_address,
        "subdomain_count": subdomain_count,
        "url_length": len(normalized),
        "findings": findings,
        "risk_contribution": score,
        "risk_level": risk_level,
        "analysis_method": "local_url_heuristics",
    }
