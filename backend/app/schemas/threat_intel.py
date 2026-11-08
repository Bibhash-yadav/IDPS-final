from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, ConfigDict


class ThreatIntelRequest(BaseModel):
    """Request model for URL threat intelligence scanning."""

    url: HttpUrl


class ThreatSourceResult(BaseModel):
    """Result returned by an individual threat intelligence source."""

    source: str
    status: Literal[
        "found",
        "not_found",
        "unavailable",
        "error",
        "provided",
    ]

    malicious: bool | None = None

    message: str | None = None

    details: dict[str, Any] | None = None


class ThreatIntelResponse(BaseModel):
    """Combined threat intelligence analysis response."""

    success: bool

    url: str
    domain: str | None = None

    threat_detected: bool = False

    threat_score: int = Field(default=0, ge=0, le=100)

    risk_level: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN",
    ] = "UNKNOWN"

    decision: Literal[
        "ALLOW",
        "WARN",
        "BLOCK",
        "REVIEW",
    ] = "REVIEW"

    matched_sources: list[str] = Field(default_factory=list)

    checked_sources: list[str] = Field(default_factory=list)

    unavailable_sources: list[str] = Field(default_factory=list)

    total_sources: int = 0

    source_results: list[dict[str, Any]] = Field(
        default_factory=list
    )

    message: str | None = None

    model_config = ConfigDict(from_attributes=True)