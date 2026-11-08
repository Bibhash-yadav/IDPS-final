
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.cloudflare_service import CloudflareService


router = APIRouter(
    prefix="/api/cloudflare",
    tags=["Cloudflare Security"],
)


class URLScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=8,
        max_length=2048,
        description="Public HTTP or HTTPS URL to scan",
    )


def get_cloudflare_service():
    try:
        return CloudflareService()
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.get("/connection")
async def cloudflare_connection():
    """Check Cloudflare API token and account connection."""

    service = get_cloudflare_service()

    try:
        result = await service.verify_connection()

        return {
            "success": True,
            "message": "Cloudflare connection checked.",
            "cloudflare": result,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


@router.post("/scan")
async def submit_url_scan(request: URLScanRequest):
    """Submit a URL to Cloudflare URL Scanner."""

    service = get_cloudflare_service()

    try:
        return await service.scan_url(request.url)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


@router.get("/scan/{scan_id}")
async def get_url_scan(scan_id: str):
    """Retrieve a Cloudflare URL Scanner report."""

    service = get_cloudflare_service()

    try:
        return await service.get_scan_result(scan_id)

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )


@router.get("/domain/{domain}")
async def domain_intelligence(domain: str):
    """Retrieve Cloudflare domain intelligence."""

    service = get_cloudflare_service()

    try:
        return await service.get_domain_intelligence(domain)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )
