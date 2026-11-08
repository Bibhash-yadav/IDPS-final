import asyncio
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit


async def check_ssl_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 7.0,
) -> dict:
    """
    Verify a server's TLS certificate using Python's trusted CA store.
    The hostname is checked against the certificate.
    """

    result = {
        "ssl_valid": False,
        "ssl_status": "NOT_CHECKED",
        "ssl_error": None,
        "ssl_message": "",
        "https_enabled": True,
    }

    if not hostname:
        result.update({
            "ssl_status": "INVALID_HOSTNAME",
            "ssl_message": "No hostname was provided.",
        })
        return result

    try:
        context = ssl.create_default_context()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                hostname,
                port,
                ssl=context,
                server_hostname=hostname,
            ),
            timeout=timeout,
        )

        ssl_object = writer.get_extra_info("ssl_object")

        if ssl_object is None:
            raise ssl.SSLError("TLS connection was not established.")

        certificate = ssl_object.getpeercert()

        writer.close()
        await writer.wait_closed()

        not_after = certificate.get("notAfter")

        if not_after:
            expiry = datetime.strptime(
                not_after,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

            if expiry <= datetime.now(timezone.utc):
                result.update({
                    "ssl_valid": False,
                    "ssl_status": "EXPIRED",
                    "ssl_message": "The SSL/TLS certificate has expired.",
                })
                return result

        result.update({
            "ssl_valid": True,
            "ssl_status": "VALID",
            "ssl_message": "The SSL/TLS certificate is valid.",
        })

    except ssl.CertificateError as exc:
        result.update({
            "ssl_valid": False,
            "ssl_status": "HOSTNAME_MISMATCH",
            "ssl_error": str(exc),
            "ssl_message": "The certificate does not match this hostname.",
        })

    except ssl.SSLCertVerificationError as exc:
        error_text = str(exc).lower()

        if "expired" in error_text:
            status = "EXPIRED"
            message = "The SSL/TLS certificate has expired."
        elif "not yet valid" in error_text:
            status = "NOT_YET_VALID"
            message = "The SSL/TLS certificate is not yet valid."
        elif "hostname" in error_text or "match" in error_text:
            status = "HOSTNAME_MISMATCH"
            message = "The certificate hostname does not match."
        else:
            status = "INVALID"
            message = "The SSL/TLS certificate could not be verified."

        result.update({
            "ssl_valid": False,
            "ssl_status": status,
            "ssl_error": str(exc),
            "ssl_message": message,
        })

    except asyncio.TimeoutError:
        result.update({
            "ssl_status": "TIMEOUT",
            "ssl_message": "TLS verification timed out.",
        })

    except (socket.gaierror, OSError, ssl.SSLError) as exc:
        result.update({
            "ssl_status": "TLS_ERROR",
            "ssl_error": str(exc),
            "ssl_message": "Could not establish a verified TLS connection.",
        })

    except Exception as exc:
        result.update({
            "ssl_status": "ERROR",
            "ssl_error": str(exc),
            "ssl_message": "An unexpected SSL verification error occurred.",
        })

    return result


async def analyze_url_signals(
    url: str,
    user_age: int | None = None,
) -> dict:
    """
    Analyze URL structure, basic suspicious indicators,
    age-related URL keywords, and actual SSL/TLS certificate status.

    This is a rule-based detector, not a complete malware scanner.
    """

    try:
        parsed = urlsplit(url.strip())
    except (TypeError, ValueError):
        return {
            "domain": "",
            "https_enabled": False,
            "ssl_valid": False,
            "ssl_status": "INVALID_URL",
            "ssl_error": "Invalid URL format.",
            "ssl_message": "The URL could not be parsed.",
            "suspicious_url": True,
            "malware_detected": False,
            "malware_confidence": 0.0,
            "malware_type": None,
            "phishing_detected": False,
            "phishing_confidence": 0.0,
            "age_restricted": False,
            "required_age": 0,
            "age_met": True,
            "age_decision": "ALLOW",
            "domain_reputation": "UNKNOWN",
            "reasons": "Invalid URL format.",
        }

    hostname = (parsed.hostname or "").lower().rstrip(".")
    https_enabled = parsed.scheme.lower() == "https"

    if not hostname:
        return {
            "domain": "",
            "https_enabled": https_enabled,
            "ssl_valid": False,
            "ssl_status": "INVALID_HOSTNAME",
            "ssl_error": "Missing hostname.",
            "ssl_message": "The URL does not contain a valid hostname.",
            "suspicious_url": True,
            "malware_detected": False,
            "malware_confidence": 0.0,
            "malware_type": None,
            "phishing_detected": False,
            "phishing_confidence": 0.0,
            "age_restricted": False,
            "required_age": 0,
            "age_met": True,
            "age_decision": "ALLOW",
            "domain_reputation": "UNKNOWN",
            "reasons": "Missing hostname.",
        }

    # Actual TLS verification. HTTP URLs are not checked for TLS.
    if https_enabled:
        ssl_result = await check_ssl_certificate(hostname)
    else:
        ssl_result = {
            "ssl_valid": False,
            "ssl_status": "NOT_APPLICABLE",
            "ssl_error": None,
            "ssl_message": "This URL uses HTTP, not HTTPS.",
            "https_enabled": False,
        }

    url_lower = url.lower()

    suspicious_keywords = (
        "login",
        "verify",
        "update",
        "account",
        "secure",
        "banking",
        "signin",
        "free",
    )

    has_suspicious_keyword = any(
        keyword in url_lower for keyword in suspicious_keywords
    )

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    suspicious_url = (
        is_ip_address
        or len(url) > 100
        or "@" in parsed.netloc
        or (has_suspicious_keyword and not https_enabled)
    )

    known_malware_domains = {
        "malware-test.com",
        "evil-payload.net",
        "phish-bank-login.com",
    }

    malware_detected = (
        hostname in known_malware_domains
        or "malware" in hostname
    )

    malware_confidence = 0.95 if malware_detected else 0.02

    malware_type = (
        "Trojan / Downloader"
        if malware_detected
        else None
    )

    phishing_detected = (
        "phish" in hostname
        or ("login" in hostname and not https_enabled)
        or is_ip_address
    )

    phishing_confidence = (
        0.89 if phishing_detected else 0.01
    )

    age_restricted_keywords = (
        "adult",
        "casino",
        "betting",
        "poker",
        "alcohol",
        "beer",
        "vapeshop",
    )

    age_restricted = any(
        keyword in url_lower
        for keyword in age_restricted_keywords
    )

    required_age = 18 if age_restricted else 0

    age_met = (
        user_age >= required_age
        if age_restricted and user_age is not None
        else not age_restricted
    )

    age_decision = "ALLOW" if age_met else "BLOCK"

    reasons = []

    if suspicious_url:
        reasons.append("Suspicious URL structure detected.")

    if malware_detected:
        reasons.append("URL matched a configured malware indicator.")

    if phishing_detected:
        reasons.append("Possible phishing indicator detected.")

    if not https_enabled:
        reasons.append("Website does not use HTTPS.")

    if https_enabled and not ssl_result["ssl_valid"]:
        reasons.append(
            ssl_result.get("ssl_message")
            or "SSL/TLS certificate verification failed."
        )

    if age_restricted and not age_met:
        reasons.append("Age restriction policy blocked this URL.")

    if not reasons:
        reasons.append(
            "No configured URL indicators were found. "
            "This does not guarantee the website is safe."
        )

    domain_reputation = (
        "MALICIOUS"
        if malware_detected
        else "SUSPICIOUS"
        if phishing_detected
        else "UNKNOWN"
    )

    return {
        "domain": hostname,
        "https_enabled": https_enabled,

        "ssl_valid": ssl_result["ssl_valid"],
        "ssl_status": ssl_result["ssl_status"],
        "ssl_error": ssl_result["ssl_error"],
        "ssl_message": ssl_result["ssl_message"],

        "malware_detected": malware_detected,
        "malware_confidence": malware_confidence,
        "malware_type": malware_type,

        "phishing_detected": phishing_detected,
        "phishing_confidence": phishing_confidence,

        "age_restricted": age_restricted,
        "required_age": required_age,
        "age_met": age_met,
        "age_decision": age_decision,

        "domain_reputation": domain_reputation,
        "suspicious_url": suspicious_url,
        "reasons": " • ".join(reasons),
    }