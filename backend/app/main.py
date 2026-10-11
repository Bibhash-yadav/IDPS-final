
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import auth, url_check, dashboard, events, protection, protection_settings


app = FastAPI(
    title="AI-Powered Intelligent Cyber Defense System",
    description=(
        "API for URL security analysis, risk scoring, "
        "and authenticated security monitoring."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/")
def root():
    return {
        "name": "IDPS API",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


app.include_router(auth.router)
app.include_router(url_check.router)
app.include_router(dashboard.router)
app.include_router(events.router)
app.include_router(protection.router)
app.include_router(protection_settings.router)