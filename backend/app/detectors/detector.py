
import asyncio
import ipaddress
import re
import socket
import ssl
import urllib.parse


# ---------------------------------------------------------
# SSL CERTIFICATE VALIDATION
# ---------------------------------------------------------

async def check_ssl_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
) -> dict:
    """
    Validate an HTTPS certificate using Python's trusted
    certificate authorities.

    Checks:
    - Certificate trust chain
    - Certificate hostname matching
    - Certificate expiration
    - TLS handshake

    This does not prove that a website is legitimate.
    """

    context = ssl.create_default_context()

    writer = None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=hostname,
                port=port,
                ssl=context,
                server_hostname=hostname,
            ),
            timeout=timeout,
        )

        # Successful TLS handshake means the certificate
        # passed the default trust and hostname checks.
        writer.close()
        await writer.wait_closed()

        return {
            "ssl_valid": True,
            "ssl_status": "VALID",
            "ssl_error": None,
            "message": (
                "SSL certificate is trusted, valid, "
                "and matches the hostname."
            ),
        }

    except ssl.SSLCertVerificationError as exc:

        error_message = str(exc)
        verification_code = getattr(exc, "verify_code", None)

        if verification_code == 10:
            status = "EXPIRED"
            message = "SSL certificate has expired."

        elif verification_code == 9:
            status = "NOT_YET_VALID"
            message = "SSL certificate is not yet valid."

        elif verification_code == 62:
            status = "HOSTNAME_MISMATCH"
            message = (
                "SSL certificate does not match the website hostname."
            )

        else:
            status = "INVALID"
            message = (
                "SSL certificate verification failed: "
                + error_message
            )

        return {
            "ssl_valid": False,
            "ssl_status": status,
            "ssl_error": error_message,
            "message": message,
        }

    except asyncio.TimeoutError:

        return {
            "ssl_valid": None,
            "ssl_status": "TIMEOUT",
            "ssl_error": "TLS connection timed out.",
            "message": "SSL verification timed out.",
        }

    except ssl.SSLError as exc:

        return {
            "ssl_valid": False,
            "ssl_status": "TLS_ERROR",
            "ssl_error": str(exc),
            "message": "TLS handshake failed.",
        }

    except (OSError, socket.gaierror) as exc:

        return {
            "ssl_valid": None,
            "ssl_status": "UNAVAILABLE",
            "ssl_error": str(exc),
            "message": (
                "Could not establish an SSL connection "
                "to the website."
            ),
        }

    except Exception as exc:

        return {
            "ssl_valid": None,
            "ssl_status": "ERROR",
            "ssl_error": str(exc),
            "message": "SSL verification could not be completed.",
        }

    finally:
        if writer is not None:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------
# URL ANALYSIS
# ---------------------------------------------------------

async def analyze_url_signals(
    url: str,
    user_age: int,
) -> dict:

    # Normalize and parse URL.

    url = url.strip()

    parsed = urllib.parse.urlparse(url)

    hostname = (parsed.hostname or "").lower().rstrip(".")

    domain = hostname

    if not hostname:
        raise ValueError("URL must contain a valid hostname.")

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port.") from exc

    # -----------------------------------------------------
    # 1. HTTPS CHECK
    # -----------------------------------------------------

    https_enabled = parsed.scheme.lower() == "https"

    # -----------------------------------------------------
    # 2. REAL SSL CERTIFICATE CHECK
    # -----------------------------------------------------

    if https_enabled:

        ssl_result = await check_ssl_certificate(
            hostname=hostname,
            port=port or 443,
        )

        ssl_valid = ssl_result["ssl_valid"]
        ssl_status = ssl_result["ssl_status"]

    else:

        ssl_valid = None
        ssl_status = "NOT_APPLICABLE"

        ssl_result = {
            "ssl_valid": None,
            "ssl_status": ssl_status,
            "ssl_error": None,
            "message": "HTTP does not use an SSL/TLS connection.",
        }

    # -----------------------------------------------------
    # 3. SUSPICIOUS URL PATTERNS
    # -----------------------------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "update",
        "account",
        "secure",
        "banking",
        "signin",
        "free",
    ]

    has_suspicious_keyword = any(
        keyword in url.lower()
        for keyword in suspicious_keywords
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
        or (
            has_suspicious_keyword
            and not https_enabled
        )
    )

    # -----------------------------------------------------
    # 4. MALWARE DETECTION
    # -----------------------------------------------------

    known_malware_domains = [
        "malware-test.com",
        "evil-payload.net",
        "phish-bank-login.com",
    ]

    malware_detected = (
        domain in known_malware_domains
        or "malware" in domain
    )

    malware_confidence = (
        0.95 if malware_detected else 0.02
    )

    malware_type = (
        "Trojan / Downloader"
        if malware_detected
        else None
    )

    # -----------------------------------------------------
    # 5. PHISHING DETECTION
    # -----------------------------------------------------

    phishing_detected = (
        "phish" in domain
        or (
            "login" in domain
            and not https_enabled
        )
        or is_ip_address
    )

    phishing_confidence = (
        0.89 if phishing_detected else 0.01
    )

    # -----------------------------------------------------
    # 6. AGE RESTRICTION
    # -----------------------------------------------------

    age_restricted_keywords = [
        "adult",
        "casino",
        "betting",
        "poker",
        "alcohol",
        "beer",
        "vapeshop",
    ]

    is_age_restricted = any(
        keyword in url.lower()
        for keyword in age_restricted_keywords
    )

    required_age = 18 if is_age_restricted else 0

    age_met = (
        user_age >= required_age
        if is_age_restricted
        else True
    )

    age_decision = (
        "ALLOW" if age_met else "BLOCK"
    )

    # -----------------------------------------------------
    # 7. BUILD DETECTION REASONS
    # -----------------------------------------------------

    reasons = []

    if malware_detected:
        reasons.append(
            "Malware indicators detected in URL pattern."
        )

    if phishing_detected:
        reasons.append(
            "Credential harvesting or phishing pattern recognized."
        )

    if suspicious_url:
        reasons.append(
            "Suspicious URL structure or IP-based hostname."
        )

    if not https_enabled:
        reasons.append(
            "Insecure HTTP protocol used."
        )

    # SSL findings.

    if ssl_status == "HOSTNAME_MISMATCH":
        reasons.append(
            "SSL certificate hostname does not match the website."
        )

    elif ssl_status == "EXPIRED":
        reasons.append(
            "SSL certificate has expired."
        )

    elif ssl_status == "NOT_YET_VALID":
        reasons.append(
            "SSL certificate is not yet valid."
        )

    elif ssl_status in ("INVALID", "TLS_ERROR"):
        reasons.append(
            "SSL/TLS certificate validation failed."
        )

    elif ssl_status in ("TIMEOUT", "UNAVAILABLE", "ERROR"):
        reasons.append(
            "SSL verification could not be completed."
        )

    if is_age_restricted and not age_met:
        reasons.append(
            f"Age restriction not met (Required: {required_age}+)."
        )

    if not reasons:
        reasons.append(
            "No known threats or anomalies detected."
        )

    # -----------------------------------------------------
    # 8. FINAL ANALYSIS RESPONSE
    # -----------------------------------------------------

    return {
        "url": url,

        "domain": domain,

        "https_enabled": https_enabled,

        "ssl_valid": ssl_valid,

        "ssl_status": ssl_status,

        "ssl_error": ssl_result.get("ssl_error"),

        "ssl_message": ssl_result.get("message"),

        "malware_detected": malware_detected,

        "malware_confidence": malware_confidence,

        "malware_type": malware_type,

        "phishing_detected": phishing_detected,

        "phishing_confidence": phishing_confidence,

        "age_restricted": is_age_restricted,

        "required_age": required_age,

        "age_met": age_met,

        "age_decision": age_decision,

        "domain_reputation": (
            "MALICIOUS"
            if malware_detected
            else "SUSPICIOUS"
            if phishing_detected
            else "UNKNOWN"
        ),

        "suspicious_url": suspicious_url,

        "reasons": " • ".join(reasons),
    }
