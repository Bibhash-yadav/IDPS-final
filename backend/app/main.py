
import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# =====================================================
# ENVIRONMENT CONFIGURATION
# =====================================================

load_dotenv()


def get_allowed_origins() -> list[str]:
    origins = {
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    }

    frontend_url = os.getenv(
        "FRONTEND_URL",
        "https://idps-fp.vercel.app",
    ).strip()

    if frontend_url:
        origins.add(frontend_url.rstrip("/"))

    additional_origins = os.getenv(
        "ALLOWED_ORIGINS",
        "",
    )

    for origin in additional_origins.split(","):
        origin = origin.strip()

        if origin:
            origins.add(origin.rstrip("/"))

    return sorted(origins)


ALLOWED_ORIGINS = get_allowed_origins()

ALLOWED_ORIGIN_REGEX = os.getenv(
    "ALLOWED_ORIGIN_REGEX"
)


# =====================================================
# APPLICATION ROUTES
# =====================================================

from app.routes import (
    auth,
    url_check,
    dashboard,
    events,
    protection,
    protection_settings,
)

from app.routes.extension_download import (
    router as extension_download_router,
)

from app.routers.cloudflare import (
    router as cloudflare_router,
)

from app.routers import threat_intel


# =====================================================
# FASTAPI APPLICATION
# =====================================================

app = FastAPI(
    title="AI-Powered Intelligent Cyber Defense System",
    description=(
        "API for URL security analysis, risk scoring, "
        "mandatory two-factor authentication, "
        "OAuth authentication, and security monitoring."
    ),
    version="1.2.0",
)


# =====================================================
# CORS CONFIGURATION
# =====================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX or None,
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
    expose_headers=[
        "Content-Disposition",
    ],
    max_age=600,
)


# =====================================================
# ROOT ENDPOINT
# =====================================================

@app.get("/")
def root():
    return {
        "name": "IDPS API",
        "status": "running",
        "version": "1.2.0",
        "docs": "/docs",
    }


# =====================================================
# HEALTH CHECK
# =====================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
    }


# =====================================================
# AUTHENTICATION
# =====================================================

app.include_router(auth.router)


# =====================================================
# EXISTING APPLICATION ROUTES
# =====================================================

app.include_router(url_check.router)
app.include_router(dashboard.router)
app.include_router(events.router)
app.include_router(protection.router)
app.include_router(protection_settings.router)

app.include_router(
    extension_download_router
)


# =====================================================
# THREAT INTELLIGENCE
# =====================================================

app.include_router(cloudflare_router)
app.include_router(threat_intel.router)
