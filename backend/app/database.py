
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker


# =====================================================
# ENVIRONMENT CONFIGURATION
# =====================================================

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL or DATABASE_URL.strip() in ("", "-"):
    raise RuntimeError(
        "DATABASE_URL is missing or invalid. "
        "Configure your PostgreSQL connection URL in backend/.env"
    )


# =====================================================
# DATABASE URL CONFIGURATION
# =====================================================

try:
    database_url = make_url(DATABASE_URL.strip())

    # Explicitly use Psycopg 3 for PostgreSQL.
    if database_url.drivername in (
        "postgresql",
        "postgres",
    ):
        database_url = database_url.set(
            drivername="postgresql+psycopg"
        )

except Exception:
    raise RuntimeError(
        "DATABASE_URL is invalid. Check your database URL format."
    )


# =====================================================
# DATABASE ENGINE
# =====================================================

engine = create_engine(
    database_url,
    pool_pre_ping=True,
    pool_recycle=1800,
    pool_size=5,
    max_overflow=10,
    connect_args={
        "connect_timeout": 10,
    },
)


# =====================================================
# SESSION CONFIGURATION
# =====================================================

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


# =====================================================
# BASE MODEL
# =====================================================

class Base(DeclarativeBase):
    pass


# =====================================================
# DATABASE DEPENDENCY
# =====================================================

def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()
