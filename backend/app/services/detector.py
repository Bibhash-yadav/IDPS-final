import urllib.parse
import re

async def analyze_url_signals(url: str, user_age: int) -> dict:
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc or parsed.path

    # HTTPS & SSL Checks
    https_enabled = parsed.scheme == "https"
    ssl_valid = https_enabled # simulated verification for demo robust fallback

    # Suspicious URL patterns
    suspicious_keywords = ["login", "verify", "update", "account", "secure", "banking", "signin", "free"]
    has_suspicious_keyword = any(kw in url.lower() for kw in suspicious_keywords)
    is_ip_address = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain))
    suspicious_url = is_ip_address or len(url) > 100 or url.count("@") > 0 or (has_suspicious_keyword and not https_enabled)

    # Malware & Phishing heuristics (Local Fallback + Intelligence simulation)
    known_malware_domains = ["malware-test.com", "evil-payload.net", "phish-bank-login.com"]
    malware_detected = domain in known_malware_domains or "malware" in domain
    malware_confidence = 0.95 if malware_detected else 0.02
    malware_type = "Trojan / Downloader" if malware_detected else None

    phishing_detected = "phish" in domain or ("login" in domain and not https_enabled) or is_ip_address
    phishing_confidence = 0.89 if phishing_detected else 0.01

    # Age Restriction Check (e.g., adult, gambling)
    age_restricted_keywords = ["adult", "casino", "betting", "poker", "alcohol", "beer", "vapeshop"]
    is_age_restricted = any(kw in url.lower() for kw in age_restricted_keywords)
    required_age = 18 if is_age_restricted else 0
    age_met = user_age >= required_age if is_age_restricted else True
    age_decision = "ALLOW" if age_met else "BLOCK"

    reasons = []
    if malware_detected:
        reasons.append("Malware indicators detected in URL pattern.")
    if phishing_detected:
        reasons.append("Credential harvesting or phishing pattern recognized.")
    if suspicious_url:
        reasons.append("Suspicious URL structure or IP-based hostname.")
    if not https_enabled:
        reasons.append("Insecure HTTP protocol used.")
    if is_age_restricted and not age_met:
        reasons.append(f"Age restriction not met (Required: {required_age}+).")

    if not reasons:
        reasons.append("No known threats or anomalies detected.")

    return {
        "domain": domain,
        "https_enabled": https_enabled,
        "ssl_valid": ssl_valid,
        "ssl_status": "VALID" if ssl_valid else "FAILED",
        "malware_detected": malware_detected,
        "malware_confidence": malware_confidence,
        "malware_type": malware_type,
        "phishing_detected": phishing_detected,
        "phishing_confidence": phishing_confidence,
        "age_restricted": is_age_restricted,
        "required_age": required_age,
        "age_met": age_met,
        "age_decision": age_decision,
        "domain_reputation": "MALICIOUS" if malware_detected else ("SUSPICIOUS" if phishing_detected else "GOOD"),
        "suspicious_url": suspicious_url,
        "reasons": " • ".join(reasons)
    }