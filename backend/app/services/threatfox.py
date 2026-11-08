import os
import logging
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def normalize_ioc(value: str) -> str:
    value = value.strip()

    if not value:
        raise ValueError("IOC cannot be empty")

    if "://" in value:
        parsed = urlparse(value)

        if not parsed.hostname:
            raise ValueError("Invalid URL")

        return parsed.hostname.lower()

    return value.lower().strip("/")


async def check_threatfox(ioc: str) -> dict[str, Any]:

    try:
        search_term = normalize_ioc(ioc)

    except ValueError as exc:
        return {
            "source": "ThreatFox",
            "status": "error",
            "malicious": None,
            "ioc": ioc,
            "message": str(exc),
        }

    auth_key = os.getenv("THREATFOX_AUTH_KEY", "").strip()

    if not auth_key:
        return {
            "source": "ThreatFox",
            "status": "unavailable",
            "malicious": None,
            "ioc": search_term,
            "message": "ThreatFox Auth-Key is not configured.",
        }

    headers = {
        "Auth-Key": auth_key,
        "User-Agent": "IDPS-Threat-Intelligence/1.0",
    }

    payload = {
        "query": "search_ioc",
        "search_term": search_term,
        "exact_match": True,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                THREATFOX_API_URL,
                json=payload,
                headers=headers,
            )

            response.raise_for_status()
            data = response.json()

        query_status = data.get("query_status")

        if query_status == "no_result":
            return {
                "source": "ThreatFox",
                "status": "not_found",
                "malicious": False,
                "ioc": search_term,
                "matches": [],
                "message": "IOC was not found in ThreatFox.",
            }

        if query_status != "ok":
            return {
                "source": "ThreatFox",
                "status": "unavailable",
                "malicious": None,
                "ioc": search_term,
                "message": f"ThreatFox returned: {query_status}",
            }

        records = data.get("data") or []

        matches = []

        for record in records:
            matches.append({
                "id": record.get("id"),
                "ioc": record.get("ioc"),
                "ioc_type": record.get("ioc_type"),
                "threat_type": record.get("threat_type"),
                "malware": (
                    record.get("malware_printable")
                    or record.get("malware")
                ),
                "confidence_level": record.get("confidence_level"),
                "first_seen": record.get("first_seen"),
                "last_seen": record.get("last_seen"),
                "reference": record.get("reference"),
                "tags": record.get("tags") or [],
            })

        if not matches:
            return {
                "source": "ThreatFox",
                "status": "not_found",
                "malicious": False,
                "ioc": search_term,
                "matches": [],
                "message": "No matching IOC records found.",
            }

        return {
            "source": "ThreatFox",
            "status": "found",
            "malicious": True,
            "ioc": search_term,
            "matches": matches,
            "match_count": len(matches),
            "message": "IOC found in ThreatFox database.",
        }

    except httpx.TimeoutException:
        return {
            "source": "ThreatFox",
            "status": "unavailable",
            "malicious": None,
            "ioc": search_term,
            "message": "ThreatFox request timed out.",
        }

    except httpx.HTTPStatusError as exc:
        logger.error("ThreatFox HTTP error: %s", exc)

        return {
            "source": "ThreatFox",
            "status": "unavailable",
            "malicious": None,
            "ioc": search_term,
            "message": f"HTTP error: {exc.response.status_code}",
        }

    except (httpx.RequestError, ValueError) as exc:
        logger.error("ThreatFox error: %s", exc)

        return {
            "source": "ThreatFox",
            "status": "unavailable",
            "malicious": None,
            "ioc": search_term,
            "message": "Could not retrieve ThreatFox intelligence.",
        }