
import logging

from fastapi import APIRouter, HTTPException

from app.schemas.threat_intel import (
    ThreatIntelRequest,
    ThreatIntelResponse,
)
from app.services.threat_engine import analyze_threat


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/threat-intel",
    tags=["Threat Intelligence"],
)


@router.post(
    "/scan",
    response_model=ThreatIntelResponse,
    summary="Scan a URL using Threat Intelligence",
    description=(
        "Analyze a URL using multiple threat intelligence sources: "
        "URLhaus, ThreatFox, OpenPhish, and Cloudflare."
    ),
)
async def scan_threat_intelligence(
    request: ThreatIntelRequest,
):
    """
    Scan a URL using multiple threat intelligence sources.

    Sources:
    - URLhaus
    - ThreatFox
    - OpenPhish
    - Cloudflare URL Scanner
    - Cloudflare Domain Intelligence

    Returns:
    - Threat score
    - Risk level
    - Security decision
    - Matched sources
    - Checked sources
    - Unavailable sources
    - Individual source results
    """

    try:
        result = await analyze_threat(
            url=str(request.url),
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=400,
                detail=result.get(
                    "error",
                    "Threat intelligence scan failed.",
                ),
            )

        return result

    except HTTPException:
        raise

    except Exception:
        logger.exception(
            "Threat intelligence scan failed."
        )

        raise HTTPException(
            status_code=500,
            detail="Internal threat intelligence error.",
        )
