
import httpx

from fastapi import APIRouter, HTTPException
from app.services.cloudflare_service import CloudflareService

router = APIRouter(
    prefix="/api/cloudflare",
    tags=["Cloudflare Security"]
)


@router.get("/connection")
async def cloudflare_connection():
    try:
        service = CloudflareService()
        result = await service.verify_connection()

        return {
            "success": True,
            "message": "Cloudflare connected successfully",
            "cloudflare": result
        }

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc)
        )
