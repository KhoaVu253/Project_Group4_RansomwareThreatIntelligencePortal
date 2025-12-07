import logging
import os
from functools import lru_cache
from typing import Dict, Tuple

from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import scoped_session, sessionmaker, declarative_base

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH)

logger = logging.getLogger(__name__)


def _engine_kwargs(url: str) -> Dict[str, object]:
    kwargs: Dict[str, object] = {"pool_pre_ping": True, "future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return kwargs


def _default_sqlite_path() -> str:
    data_dir = os.path.join(BASE_DIR, "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "app.db")


@lru_cache()
def _resolve_database_target() -> Tuple[str, bool]:
    """Return (database_url, allow_fallback_to_sqlite)."""
    explicit_url = os.getenv("DATABASE_URL")
    if explicit_url:
        return explicit_url, False

    driver = (os.getenv("DB_DRIVER") or "mysql").lower()
    if driver == "sqlite":
        sqlite_path = os.getenv("SQLITE_PATH") or _default_sqlite_path()
        return f"sqlite:///{sqlite_path}", False

    host = os.getenv("DB_HOST", "127.0.0.1")
    port = os.getenv("DB_PORT", "3306")
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASSWORD", "")
    database = os.getenv("DB_NAME", "ransomware_portal")

    if not user:
        raise RuntimeError("Database user is not configured. Set DB_USER in environment.")

    allow_fallback = (os.getenv("ALLOW_SQLITE_FALLBACK", "1") or "1").lower() not in {"0", "false", "no"}
    return f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}?charset=utf8mb4", allow_fallback


def _initialise_engine() -> Tuple[object, str, bool]:
    target_url, allow_fallback = _resolve_database_target()
    engine_candidate = create_engine(target_url, **_engine_kwargs(target_url))

    try:
        with engine_candidate.connect() as connection:
            connection.execute(text("SELECT 1"))
        return engine_candidate, target_url, target_url.startswith("sqlite")
    except OperationalError as exc:
        if not allow_fallback:
            raise

        fallback_path = os.getenv("SQLITE_FALLBACK_PATH") or _default_sqlite_path()
        fallback_url = f"sqlite:///{fallback_path}"
        logger.warning(
            "Failed to connect to database at %s (%s). Falling back to SQLite at %s.",
            target_url,
            exc,
            fallback_url,
        )

        fallback_engine = create_engine(fallback_url, **_engine_kwargs(fallback_url))
        with fallback_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return fallback_engine, fallback_url, True


engine, DATABASE_URL, USING_SQLITE = _initialise_engine()

SessionLocal = scoped_session(
    sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
)

Base = declarative_base()


def init_database() -> None:
    """Create database tables if they do not exist."""
    try:
        from . import models  # noqa: F401
    except ImportError:
        import models  # type: ignore  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_two_factor_columns()
    _ensure_email_otp_purpose()
    _ensure_login_security_columns()


def get_session():
    """Provide a new SQLAlchemy session."""
    return SessionLocal()


def _ensure_two_factor_columns() -> None:
    """Add missing 2FA columns on existing databases without full migrations."""
    try:
        inspector = inspect(engine)
        if "users" not in inspector.get_table_names():
            return

        existing = {col["name"] for col in inspector.get_columns("users")}
        statements = []
        added = []
        dialect = engine.dialect.name

        if "two_factor_enabled" not in existing:
            added.append("two_factor_enabled")
            if dialect == "mysql":
                statements.append(
                    "ALTER TABLE users "
                    "ADD COLUMN two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER last_login_at"
                )
            elif dialect == "sqlite":
                statements.append(
                    "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0"
                )
            else:
                statements.append(
                    "ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE"
                )

        if "two_factor_secret" not in existing:
            added.append("two_factor_secret")
            if dialect == "mysql":
                statements.append(
                    "ALTER TABLE users "
                    "ADD COLUMN two_factor_secret VARCHAR(32) NULL AFTER two_factor_enabled"
                )
            else:
                statements.append("ALTER TABLE users ADD COLUMN two_factor_secret VARCHAR(32)")

        if "two_factor_backup_codes" not in existing:
            added.append("two_factor_backup_codes")
            # JSON works on MySQL 5.7+ and falls back to TEXT on SQLite.
            column_type = "JSON" if dialect == "mysql" else "JSON"
            statements.append(
                f"ALTER TABLE users ADD COLUMN two_factor_backup_codes {column_type} NULL"
                + (" AFTER two_factor_secret" if dialect == "mysql" else "")
            )

        if not statements:
            return

        with engine.begin() as conn:
            for stmt in statements:
                conn.execute(text(stmt))

        logger.info("Added missing 2FA columns to users table: %s", ", ".join(added))
    except Exception:
        logger.exception("Failed to ensure 2FA columns exist on users table")


def _ensure_email_otp_purpose() -> None:
    """Add purpose column to email_otps if missing."""
    try:
        inspector = inspect(engine)
        if "email_otps" not in inspector.get_table_names():
            return
        existing = {col["name"] for col in inspector.get_columns("email_otps")}
        if "purpose" in existing:
            return
        with engine.begin() as conn:
            dialect = engine.dialect.name
            if dialect == "mysql":
                conn.execute(
                    text(
                        "ALTER TABLE email_otps "
                        "ADD COLUMN purpose VARCHAR(32) NOT NULL DEFAULT 'register' AFTER created_at"
                    )
                )
            else:
                conn.execute(
                    text("ALTER TABLE email_otps ADD COLUMN purpose VARCHAR(32) NOT NULL DEFAULT 'register'")
                )
        logger.info("Added purpose column to email_otps table")
    except Exception:
        logger.exception("Failed to ensure purpose column on email_otps table")


def _ensure_login_security_columns() -> None:
    """Add failed_login_attempts and locked_until to users if missing."""
    try:
        inspector = inspect(engine)
        if "users" not in inspector.get_table_names():
            return
        existing = {col["name"] for col in inspector.get_columns("users")}
        statements = []
        if "failed_login_attempts" not in existing:
            statements.append("ALTER TABLE users ADD COLUMN failed_login_attempts INT NOT NULL DEFAULT 0")
        if "locked_until" not in existing:
            statements.append("ALTER TABLE users ADD COLUMN locked_until DATETIME NULL")
        if not statements:
            return
        with engine.begin() as conn:
            for stmt in statements:
                conn.execute(text(stmt))
        logger.info("Added login security columns to users table")
    except Exception:
        logger.exception("Failed to ensure login security columns on users table")
