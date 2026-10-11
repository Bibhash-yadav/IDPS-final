from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user") # user, admin
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class URLCheckRecord(Base):
    __tablename__ = "url_checks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    url = Column(String, nullable=False, index=True)
    domain = Column(String, nullable=False, index=True)
    age_verified = Column(Integer, nullable=False)
    https_enabled = Column(Boolean, default=False)
    ssl_valid = Column(Boolean, default=False)
    ssl_status = Column(String, default="UNKNOWN")
    malware_detected = Column(Boolean, default=False)
    malware_confidence = Column(Float, default=0.0)
    malware_type = Column(String, nullable=True)
    phishing_detected = Column(Boolean, default=False)
    phishing_confidence = Column(Float, default=0.0)
    age_restricted = Column(Boolean, default=False)
    required_age = Column(Integer, default=0)
    age_decision = Column(String, default="ALLOW")
    domain_reputation = Column(String, default="GOOD")
    risk_score = Column(Integer, default=0)
    risk_level = Column(String, default="LOW")
    decision = Column(String, default="ALLOW")
    reasons = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, index=True, nullable=False)
    source = Column(String, nullable=False)
    risk = Column(Integer, default=0)
    severity = Column(String, default="INFO")
    decision = Column(String, default="ALLOW")
    status = Column(String, default="RESOLVED")
    details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class BlockedDomain(Base):
    __tablename__ = "blocked_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class AllowedDomain(Base):
    __tablename__ = "allowed_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())