
import os
import re
import asyncio
import logging
import ipaddress

from typing import Any
from urllib.parse import urlsplit

import httpx
from dotenv import load_dotenv


# ==========================================
# CONFIGURATION
# ==========================================

load_dotenv()

logger = logging.getLogger(__name__)

CLOUDFLARE_BASE_URL = (
    "https://api.cloudflare.com/client/v4"
)

CLOUDFLARE_TIMEOUT = float(
    os.getenv("CLOUDFLARE_TIMEOUT", "30")
)

CLOUDFLARE_POLL_ATTEMPTS = int(
    os.getenv("CLOUDFLARE_POLL_ATTEMPTS", "10")
)

CLOUDFLARE_POLL_INTERVAL = float(
    os.getenv("CLOUDFLARE_POLL_INTERVAL", "3")
)


# ==========================================
# CLOUDFLARE SERVICE
# ==========================================

class CloudflareService:

    def __init__(self):

        self.account_id = os.getenv(
            "CLOUDFLARE_ACCOUNT_ID", ""
        ).strip()

        self.api_token = os.getenv(
            "CLOUDFLARE_API_TOKEN", ""
        ).strip()

        if not self.account_id or not self.api_token:
            raise ValueError(
                "CLOUDFLARE_ACCOUNT_ID or "
                "CLOUDFLARE_API_TOKEN is missing "
                "from the backend .env file."
            )

        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "User-Agent": "IDPS-Threat-Intelligence/1.0",
        }

    # ======================================
    # COMMON API REQUEST
    # ======================================

    async def _request(
        self,
        method: str,
        endpoint: str,
        allow_not_ready: bool = False,
        **kwargs,
    ) -> dict[str, Any]:

        url = f"{CLOUDFLARE_BASE_URL}{endpoint}"

        try:
            async with httpx.AsyncClient(
                timeout=CLOUDFLARE_TIMEOUT
            ) as client:

                response = await client.request(
                    method=method,
                    url=url,
                    headers=self.headers,
                    **kwargs,
                )

        except httpx.TimeoutException as exc:
            raise RuntimeError(
                "Cloudflare API request timed out."
            ) from exc

        except httpx.RequestError as exc:
            raise RuntimeError(
                f"Cloudflare connection error: {exc}"
            ) from exc

        # Only scan-result requests can treat 404 as pending.
        if response.status_code == 404 and allow_not_ready:
            return {
                "success": False,
                "processing": True,
                "message": "Cloudflare scan is not ready yet.",
            }

        try:
            data = response.json()
        except ValueError:
            data = {
                "message": response.text[:500]
            }

        if response.is_error:

            errors = (
                data.get("errors", [])
                if isinstance(data, dict)
                else []
            )

            messages = []

            for error in errors:
                if isinstance(error, dict):
                    messages.append(
                        str(error.get("message", error))
                    )
                else:
                    messages.append(str(error))

            message = (
                "; ".join(messages)
                or data.get(
                    "message",
                    "Cloudflare API request failed.",
                )
                if isinstance(data, dict)
                else "Cloudflare API request failed."
            )

            raise RuntimeError(
                f"Cloudflare API error "
                f"({response.status_code}): {message}"
            )

        if not isinstance(data, dict):
            raise RuntimeError(
                "Unexpected response from Cloudflare."
            )

        if data.get("success") is False:
            errors = data.get("errors", [])

            message = "; ".join(
                str(error.get("message", error))
                if isinstance(error, dict)
                else str(error)
                for error in errors
            )

            raise RuntimeError(
                message or "Cloudflare reported an unsuccessful request."
            )

        return data

    # ======================================
    # URL VALIDATION
    # ======================================

    @staticmethod
    def validate_url(url: str) -> str:

        if not isinstance(url, str) or not url.strip():
            raise ValueError("Please provide a URL.")

        url = url.strip()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            parsed = urlsplit(url)

            if parsed.scheme not in ("http", "https"):
                raise ValueError(
                    "Only HTTP and HTTPS URLs are allowed."
                )

            if not parsed.hostname:
                raise ValueError("Please provide a valid URL.")

            if parsed.username or parsed.password:
                raise ValueError(
                    "URLs containing credentials are not allowed."
                )

            _ = parsed.port

        except ValueError as exc:
            raise ValueError(
                f"Invalid URL: {exc}"
            ) from exc

        hostname = parsed.hostname.lower()

        if hostname in (
            "localhost",
            "localhost.localdomain",
        ):
            raise ValueError(
                "Localhost URLs cannot be scanned."
            )

        try:
            address = ipaddress.ip_address(hostname)

            if not address.is_global:
                raise ValueError(
                    "Private, loopback and reserved IP "
                    "addresses cannot be scanned."
                )

        except ValueError as exc:
            if "cannot be scanned" in str(exc):
                raise

        return parsed.geturl()

    # ======================================
    # DOMAIN VALIDATION
    # ======================================

    @staticmethod
    def validate_domain(domain: str) -> str:

        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("Please provide a domain.")

        domain = domain.strip().lower().rstrip(".")

        if "://" in domain or "/" in domain:
            raise ValueError(
                "Enter a domain such as example.com."
            )

        if len(domain) > 253 or "." not in domain:
            raise ValueError(
                "Please enter a valid domain name."
            )

        if any(char.isspace() for char in domain):
            raise ValueError(
                "Domain cannot contain spaces."
            )

        if not re.fullmatch(
            r"[a-z0-9.-]+",
            domain,
        ):
            raise ValueError(
                "Domain contains invalid characters."
            )

        if ".." in domain or domain.startswith(".") or domain.startswith("-"):
            raise ValueError("Invalid domain name.")

        return domain

    # ======================================
    # VERIFY CONNECTION
    # ======================================

    async def verify_connection(self):

        data = await self._request(
            "GET",
            f"/accounts/{self.account_id}/tokens/verify",
        )

        result = data.get("result") or {}

        return {
            "connected": result.get("status") == "active",
            "token_status": result.get("status"),
            "account_id": self.account_id,
            "token_id": result.get("id"),
        }

    # ======================================
    # SUBMIT URL SCAN
    # ======================================

    async def scan_url(self, url: str):

        safe_url = self.validate_url(url)

        data = await self._request(
            "POST",
            f"/accounts/{self.account_id}/urlscanner/v2/scan",
            json={
                "url": safe_url,
                "visibility": "unlisted",
            },
        )

        scan_id = data.get("uuid")

        if not scan_id:
            result = data.get("result", {})

            if isinstance(result, dict):
                scan_id = result.get("uuid")

        if not scan_id:
            raise RuntimeError(
                "Cloudflare did not return a scan UUID."
            )

        return {
            "success": True,
            "scan_id": scan_id,
            "url": safe_url,
            "visibility": data.get("visibility", "unlisted"),
            "message": "URL successfully submitted to Cloudflare Scanner.",
        }

    # ======================================
    # GET SCAN RESULT
    # ======================================

    async def get_scan_result(self, scan_id: str):

        if not scan_id or not isinstance(scan_id, str):
            raise ValueError(
                "A valid Cloudflare scan ID is required."
            )

        data = await self._request(
            "GET",
            (
                f"/accounts/{self.account_id}"
                f"/urlscanner/v2/result/{scan_id}"
            ),
            allow_not_ready=True,
        )

        if data.get("processing"):
            return {
                "success": False,
                "processing": True,
                "scan_id": scan_id,
                "message": "Cloudflare scan is still processing.",
            }

        result = data.get("result", data)

        return {
            "success": True,
            "processing": False,
            "scan_id": scan_id,
            "report": result,
        }

    # ======================================
    # WAIT FOR SCAN RESULT
    # ======================================

    async def wait_for_scan_result(
        self,
        scan_id: str,
        attempts: int | None = None,
        interval: float | None = None,
    ):

        max_attempts = (
            attempts
            if attempts is not None
            else CLOUDFLARE_POLL_ATTEMPTS
        )

        delay = (
            interval
            if interval is not None
            else CLOUDFLARE_POLL_INTERVAL
        )

        for attempt in range(max_attempts):

            result = await self.get_scan_result(scan_id)

            if result.get("success"):
                return result

            if not result.get("processing"):
                return result

            logger.info(
                "Cloudflare scan %s is processing (%s/%s).",
                scan_id,
                attempt + 1,
                max_attempts,
            )

            if attempt < max_attempts - 1:
                await asyncio.sleep(delay)

        return {
            "success": False,
            "processing": True,
            "scan_id": scan_id,
            "message": (
                "Cloudflare scan is still processing. "
                "Check the scan again later."
            ),
        }

    # ======================================
    # DOMAIN INTELLIGENCE
    # ======================================

    async def get_domain_intelligence(self, domain: str):

        safe_domain = self.validate_domain(domain)

        data = await self._request(
            "GET",
            f"/accounts/{self.account_id}/intel/domain",
            params={
                "domain": safe_domain,
            },
        )

        return {
            "success": True,
            "domain": safe_domain,
            "intelligence": data.get("result"),
        }
