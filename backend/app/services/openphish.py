
import logging
import os
import time

from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from dotenv import load_dotenv


# ==========================================
# CONFIGURATION
# ==========================================

load_dotenv()

logger = logging.getLogger(__name__)

OPENPHISH_FEED_URL = os.getenv(
    "OPENPHISH_FEED_URL",
    "https://openphish.com/feed.txt",
)

OPENPHISH_FALLBACK_URL = (
    "https://raw.githubusercontent.com/"
    "openphish/public_feed/refs/heads/main/feed.txt"
)

FEED_CACHE_TTL = int(
    os.getenv("OPENPHISH_CACHE_TTL", "3600")
)

FEED_TIMEOUT = float(
    os.getenv("OPENPHISH_TIMEOUT", "30")
)

_cached_urls: set[str] = set()
_last_updated = 0.0


# ==========================================
# URL NORMALIZATION
# ==========================================

def normalize_url(url: str) -> str:
    """Normalize URL for exact feed matching."""

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

    hostname = parsed.hostname.lower()

    port = parsed.port

    if port and not (
        (parsed.scheme == "http" and port == 80)
        or (parsed.scheme == "https" and port == 443)
    ):
        hostname = f"{hostname}:{port}"

    path = parsed.path or "/"

    return urlunsplit((
        parsed.scheme.lower(),
        hostname,
        path,
        parsed.query,
        "",
    ))


# ==========================================
# DOWNLOAD FEED
# ==========================================

async def download_feed(
    client: httpx.AsyncClient,
    feed_url: str,
) -> set[str]:

    response = await client.get(
        feed_url,
        headers={
            "User-Agent": "Mozilla/5.0 IDPS-Threat-Intelligence/1.0",
            "Accept": "text/plain,*/*",
        },
    )

    response.raise_for_status()

    urls = set()

    for line in response.text.splitlines():

        line = line.strip()

        if not line:
            continue

        try:
            normalized = normalize_url(line)
            urls.add(normalized)

        except ValueError:
            continue

    if not urls:
        raise ValueError(
            f"Feed returned no valid URLs: {feed_url}"
        )

    return urls


# ==========================================
# GET PHISHING FEED
# ==========================================

async def get_phishing_feed(
    force_refresh: bool = False,
) -> set[str]:
    """
    Download and cache OpenPhish community feed.

    Uses primary feed first and official GitHub
    community feed as fallback.
    """

    global _cached_urls, _last_updated

    current_time = time.time()

    # Use cached feed when still valid.
    if (
        _cached_urls
        and not force_refresh
        and current_time - _last_updated < FEED_CACHE_TTL
    ):
        return _cached_urls

    feed_urls = [
        OPENPHISH_FEED_URL,
        OPENPHISH_FALLBACK_URL,
    ]

    errors = []

    async with httpx.AsyncClient(
        timeout=FEED_TIMEOUT,
        follow_redirects=True,
    ) as client:

        for feed_url in feed_urls:

            try:
                urls = await download_feed(
                    client,
                    feed_url,
                )

                _cached_urls = urls
                _last_updated = time.time()

                logger.info(
                    "OpenPhish feed loaded: %s URLs from %s",
                    len(urls),
                    feed_url,
                )

                return _cached_urls

            except Exception as exc:

                logger.warning(
                    "OpenPhish feed failed (%s): %s",
                    feed_url,
                    exc,
                )

                errors.append(
                    f"{feed_url}: {str(exc)}"
                )

    # Use previously downloaded cache if available.
    if _cached_urls:
        logger.warning(
            "Using previously cached OpenPhish feed."
        )

        return _cached_urls

    raise RuntimeError(
        "All OpenPhish feed sources failed. "
        + " | ".join(errors)
    )


# ==========================================
# CHECK OPENPHISH
# ==========================================

async def check_openphish(
    url: str,
) -> dict[str, Any]:
    """
    Check whether URL exists in OpenPhish feed.

    Possible statuses:
        found
        not_found
        unavailable
        error
    """

    try:
        normalized_url = normalize_url(url)

    except ValueError as exc:
        return {
            "source": "OpenPhish",
            "status": "error",
            "malicious": None,
            "url": url,
            "message": str(exc),
        }

    try:
        feed = await get_phishing_feed()

        if normalized_url in feed:
            return {
                "source": "OpenPhish",
                "status": "found",
                "malicious": True,
                "url": normalized_url,
                "feed_size": len(feed),
                "message": (
                    "URL found in OpenPhish phishing feed."
                ),
            }

        return {
            "source": "OpenPhish",
            "status": "not_found",
            "malicious": False,
            "url": normalized_url,
            "feed_size": len(feed),
            "message": (
                "URL not found in OpenPhish feed."
            ),
        }

    except Exception as exc:

        logger.exception("OpenPhish check failed.")

        return {
            "source": "OpenPhish",
            "status": "unavailable",
            "malicious": None,
            "url": normalized_url,
            "message": (
                f"OpenPhish feed could not be checked: {str(exc)}"
            ),
        }


# ==========================================
# CLEAR FEED CACHE
# ==========================================

def clear_openphish_cache():
    """Clear cached feed to force a fresh download."""

    global _cached_urls, _last_updated

    _cached_urls = set()
    _last_updated = 0.0
