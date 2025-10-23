import os
from functools import lru_cache

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, declarative_base

load_dotenv()


@lru_cache()
def _build_database_url() -> str:
    host = os.getenv("DB_HOST", "127.0.0.1")
    port = os.getenv("DB_PORT", "3306")
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASSWORD", "")
    database = os.getenv("DB_NAME", "ransomware_portal")

    if not user:
        raise RuntimeError("Database user is not configured. Set DB_USER in environment.")

    return f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}?charset=utf8mb4"


DATABASE_URL = _build_database_url()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = scoped_session(
    sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
)

Base = declarative_base()


def init_database() -> None:
    """Create database tables if they do not exist."""
    # Local import to avoid circular dependency.
    try:
        from . import models  # noqa: F401
    except ImportError:
        import models  # type: ignore  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_session():
    """Provide a new SQLAlchemy session."""
    return SessionLocal()
