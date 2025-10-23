from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import relationship
try:
    from .database import Base  # type: ignore
except ImportError:
    from database import Base  # type: ignore


class User(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    email = Column(String(191), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False, default="")
    full_name = Column(String(191))
    role = Column(Enum("admin", "analyst", "viewer", name="user_role"), default="analyst")
    is_active = Column(SmallInteger, nullable=False, default=1)
    last_login_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    profile = relationship("UserProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    scans = relationship("ScanRequest", back_populates="user")


class UserProfile(Base):
    __tablename__ = "user_profiles"

    user_id = Column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    display_name = Column(String(191))
    organization = Column(String(191))
    job_title = Column(String(191))
    phone_number = Column(String(50))
    bio = Column(Text)
    language = Column(String(10), default="vi")
    theme = Column(Enum("dark", "light", "system", name="theme"), default="dark")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    user = relationship("User", back_populates="profile")


class ApiClient(Base):
    __tablename__ = "api_clients"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    name = Column(String(191), nullable=False)
    api_key_hash = Column(String(64), nullable=False, unique=True)
    contact_email = Column(String(191))
    rate_limit_per_minute = Column(Integer, default=60)
    is_active = Column(SmallInteger, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    last_used_at = Column(DateTime)

    scans = relationship("ScanRequest", back_populates="api_client")


class ScanRequest(Base):
    __tablename__ = "scan_requests"
    __table_args__ = (
        UniqueConstraint("vt_analysis_id", name="uk_vt_analysis"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    api_client_id = Column(BigInteger, ForeignKey("api_clients.id", ondelete="SET NULL"))
    indicator_type = Column(Enum("file", "url", "domain", "ip_address", name="indicator"), nullable=False)
    indicator_value = Column(String(512), nullable=False)
    display_value = Column(String(512))
    vt_analysis_id = Column(String(128))
    status = Column(
        Enum("queued", "running", "completed", "error", "timeout", name="scan_status"),
        nullable=False,
        default="queued",
    )
    summary = Column(Text)
    malicious = Column(SmallInteger, default=0)
    suspicious = Column(SmallInteger, default=0)
    harmless = Column(SmallInteger, default=0)
    undetected = Column(SmallInteger, default=0)
    error_message = Column(Text)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    completed_at = Column(DateTime)

    user = relationship("User", back_populates="scans")
    api_client = relationship("ApiClient", back_populates="scans")
    vt_responses = relationship("VTResponse", back_populates="scan", cascade="all, delete-orphan")
    tags = relationship("ScanTag", back_populates="scan", cascade="all, delete-orphan")
    comments = relationship("AnalystComment", back_populates="scan", cascade="all, delete-orphan")


class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey("scan_requests.id", ondelete="CASCADE"), nullable=False)
    artifact_type = Column(Enum("file", "url", "domain", "ip_address", "note", name="artifact_type"), nullable=False)
    original_name = Column(String(255))
    file_size = Column(BigInteger)
    mime_type = Column(String(127))
    storage_path = Column(String(255))
    sha256 = Column(String(64))
    created_at = Column(DateTime, nullable=False, server_default=func.now())


class VTResponse(Base):
    __tablename__ = "vt_responses"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey("scan_requests.id", ondelete="CASCADE"), nullable=False)
    vt_status = Column(String(64))
    raw_payload = Column(JSON, nullable=False)
    received_at = Column(DateTime, nullable=False, server_default=func.now())

    scan = relationship("ScanRequest", back_populates="vt_responses")


class ScanTag(Base):
    __tablename__ = "scan_tags"
    __table_args__ = (UniqueConstraint("scan_id", "tag", name="uk_scan_tag"),)

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey("scan_requests.id", ondelete="CASCADE"), nullable=False)
    tag = Column(String(64), nullable=False)
    added_by = Column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    scan = relationship("ScanRequest", back_populates="tags")


class AnalystComment(Base):
    __tablename__ = "analyst_comments"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id = Column(BigInteger, ForeignKey("scan_requests.id", ondelete="CASCADE"), nullable=False)
    author_id = Column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    comment_body = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    scan = relationship("ScanRequest", back_populates="comments")


