
import os
import logging

from typing import Any
from urllib.parse import urlsplit

import httpx
from dotenv import load_dotenv


# ==========================================
# CONFIGURATION
# ==========================================

load_dotenv()

logger = logging.getLogger(__name__)

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

URLHAUS_TIMEOUT = float(
    os.getenv("URLHAUS_TIMEOUT", "15")
)


# ==========================================
# URL NORMALIZATION
# ==========================================

def normalize_url(url: str) -> str:
    """Normalize and validate URL."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty.")

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlsplit(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    _ = parsed.port

    return url


# ==========================================
# URLHAUS CHECK
# ==========================================

async def check_urlhaus(url: str) -> dict[str, Any]:
    """
    Check URL against URLhaus.

    Possible statuses:
        found
        not_found
        unavailable
        error
    """

    try:
        complete_url = normalize_url(url)

    except ValueError as exc:
        return {
            "source": "URLhaus",
            "status": "error",
            "malicious": None,
            "url": url,
            "message": str(exc),
        }

    # Load API key.
    auth_key = os.getenv(
        "URLHAUS_AUTH_KEY", ""
    ).strip()

    if not auth_key:
        return {
            "source": "URLhaus",
            "status": "unavailable",
            "malicious": None,
            "url": complete_url,
            "message": "URLHAUS_AUTH_KEY is missing from .env.",
        }

    headers = {
        "Auth-Key": auth_key,
        "User-Agent": "IDPS-Threat-Intelligence/1.0",
    }

    payload = {
        "url": complete_url,
    }

    try:
        async with httpx.AsyncClient(
            timeout=URLHAUS_TIMEOUT,
            follow_redirects=True,
        ) as client:

            response = await client.post(
                URLHAUS_API_URL,
                data=payload,
                headers=headers,
            )

        # Handle HTTP errors with useful diagnostics.
        if response.status_code == 401:
            return {
                "source": "URLhaus",
                "status": "unavailable",
                "malicious": None,
                "url": complete_url,
                "message": (
                    "URLhaus authentication failed (401). "
                    "Check your Auth-Key."
                ),
            }

        if response.status_code == 403:
            try:
                error_data = response.json()
            except ValueError:
                error_data = {}

            errors = error_data.get("errors", [])

            error_details = "; ".join(
                str(item.get("message", item))
                if isinstance(item, dict)
                else str(item)
                for item in errors
            )

            if not error_details:
                error_details = response.text[:300]

            logger.error(
                "URLhaus access denied: %s",
                error_details,
            )

            return {
                "source": "URLhaus",
                "status": "unavailable",
                "malicious": None,
                "url": complete_url,
                "message": (
                    "URLhaus access denied (403). "
                    "Your Auth-Key may be invalid or unrecognized. "
                    f"API details: {error_details}"
                ),
            }

        response.raise_for_status()

        data = response.json()

        query_status = data.get("query_status")

        # URL not found.
        if query_status == "no_results":
            return {
                "source": "URLhaus",
                "status": "not_found",
                "malicious": False,
                "url": complete_url,
                "threat": None,
                "tags": [],
                "date_added": None,
                "reference": None,
                "message": (
                    "URL was not found in the URLhaus database."
                ),
            }

        # Successful threat match.
        if query_status == "ok":
            return {
                "source": "URLhaus",
                "status": "found",
                "malicious": True,
                "url": complete_url,
                "threat": data.get("threat"),
                "tags": data.get("tags") or [],
                "date_added": data.get("date_added"),
                "reference": data.get("urlhaus_reference"),
                "message": (
                    "URL found in the URLhaus malware database."
                ),
            }

        # Unexpected API response.
        return {
            "source": "URLhaus",
            "status": "unavailable",
            "malicious": None,
            "url": complete_url,
            "message": (
                f"Unexpected URLhaus response: {query_status}"
            ),
        }

    except httpx.TimeoutException:
        logger.warning("URLhaus request timed out.")

        return {
            "source": "URLhaus",
            "status": "unavailable",
            "malicious": None,
            "url": complete_url,
            "message": "URLhaus request timed out.",
        }

    except httpx.HTTPStatusError as exc:
        logger.exception("URLhaus HTTP request failed.")

        return {
            "source": "URLhaus",
            "status": "unavailable",
            "malicious": None,
            "url": complete_url,
            "message": (
                f"URLhaus HTTP error: "
                f"{exc.response.status_code}"
            ),
        }

    except (httpx.RequestError, ValueError):
        logger.exception("URLhaus connection or response error.")

        return {
            "source": "URLhaus",
            "status": "unavailable",
            "malicious": None,
            "url": complete_url,
            "message": (
                "Could not retrieve URLhaus intelligence."
            ),
        }

    except Exception:
        logger.exception("Unexpected URLhaus error.")

        return {
            "source": "URLhaus",
            "status": "unavailable",
            "malicious": None,
            "url": complete_url,
            "message": "Unexpected URLhaus error.",
        }
