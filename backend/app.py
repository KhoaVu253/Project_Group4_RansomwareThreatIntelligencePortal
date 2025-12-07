import base64
import hashlib
import io
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Tuple, Optional, Dict, Any, List

import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import select, delete, func, desc, asc, or_
from sqlalchemy.exc import SQLAlchemyError

from validators import validate_indicator, sanitize_filename
from database import get_session, init_database, DATABASE_URL, USING_SQLITE
from models import (
    CommunityCategory,
    CommunityComment,
    CommunityPost,
    ScanRequest,
    User,
    UserProfile,
    VTResponse,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(__name__)
# In a production environment, you should restrict the origins.
CORS(app)


def _configure_logging() -> None:
    log_level_name = (os.getenv("LOG_LEVEL") or "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        stream=sys.stdout,
        force=True,
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(formatter)

    app.logger.handlers = []
    app.logger.addHandler(stream_handler)
    app.logger.setLevel(log_level)

    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.handlers = []
    werkzeug_logger.addHandler(stream_handler)
    werkzeug_logger.setLevel(log_level)
    werkzeug_logger.propagate = False

    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def _truncate(value: str, limit: int = 80) -> str:
    """Truncate long log values for readability."""
    if not value:
        return ""
    return value if len(value) <= limit else f"{value[:limit]}..."


def _log_database_backend() -> None:
    if USING_SQLITE:
        app.logger.info(
            "Using SQLite database at %s",
            DATABASE_URL.replace("sqlite:///", "", 1),
        )
    else:
        driver = DATABASE_URL.split("://", 1)[0]
        app.logger.info("Using database backend via %s", driver)


_configure_logging()
_log_database_backend()

COMMUNITY_MODERATOR_TOKEN = (os.getenv("COMMUNITY_MODERATOR_TOKEN") or os.getenv("COMMUNITY_MOD_TOKEN") or "").strip()
DEFAULT_COMMUNITY_CATEGORIES: List[Dict[str, Any]] = [
    {
        "slug": "news-alerts",
        "name": "News & Alerts",
        "description": "Latest ransomware reports, advisories, and intelligence alerts.",
        "display_order": 1,
    },
    {
        "slug": "help-and-decrypt",
        "name": "Help & Decrypt",
        "description": "Requests for assistance with decryptors, remediation, or triage.",
        "display_order": 2,
    },
    {
        "slug": "prevention-tips",
        "name": "Prevention Tips",
        "description": "Guidance, playbooks, and hardening checklists for defenders.",
        "display_order": 3,
    },
    {
        "slug": "incident-reports",
        "name": "Incident Reports",
        "description": "Field notes, after-action reports, and case studies.",
        "display_order": 4,
    },
    {
        "slug": "tools-and-scanners",
        "name": "Tools & Scanners",
        "description": "Utilities, signatures, and detection content shared by the community.",
        "display_order": 5,
    },
]


def ensure_default_community_categories() -> None:
    """Create baseline community categories if they do not exist."""
    session = get_session()
    try:
        existing_slugs = {slug for (slug,) in session.execute(select(CommunityCategory.slug))}
        created = 0
        for category in DEFAULT_COMMUNITY_CATEGORIES:
            if category["slug"] in existing_slugs:
                continue
            session.add(
                CommunityCategory(
                    slug=category["slug"],
                    name=category["name"],
                    description=category.get("description"),
                    display_order=category.get("display_order", 0),
                    is_active=True,
                )
            )
            created += 1
        if created:
            session.commit()
            app.logger.info("Seeded %s community categories", created)
        else:
            session.rollback()
    except Exception:
        session.rollback()
        app.logger.exception("Failed to seed community categories")
    finally:
        session.close()


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_API_URL = "https://www.virustotal.com/api/v3"
VT_MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB limit for public API
DEFAULT_TIMEOUT = (10, 120)  # (connect, read) timeouts for VT requests

# Ensure database schema is available.
try:
    init_database()
    ensure_default_community_categories()
except Exception:
    app.logger.exception("Failed to initialize database schema")
    raise


@app.before_request
def log_request_start():
    """Log incoming requests with basic metadata and timing."""
    if request.method == "OPTIONS":
        return
    g._request_started = time.perf_counter()
    app.logger.info(
        "→ %s %s (%s)",
        request.method,
        request.path,
        request.remote_addr,
    )


@app.after_request
def log_request_end(response):
    """Log outgoing responses with status and duration."""
    if request.method == "OPTIONS":
        return response
    started = getattr(g, "_request_started", None)
    duration_ms = None
    if started is not None:
        duration_ms = (time.perf_counter() - started) * 1000
    app.logger.info(
        "← %s %s %s %s",
        request.method,
        request.path,
        response.status_code,
        f"{duration_ms:.1f} ms" if duration_ms is not None else "? ms",
    )
    return response


def get_db_session():
    """Return a scoped SQLAlchemy session for the current request context."""
    if "db_session" not in g:
        g.db_session = get_session()
    return g.db_session


@app.teardown_appcontext
def teardown_db(exception=None):
    session = g.pop("db_session", None)
    if session is not None:
        session.close()


def ensure_api_key() -> Tuple[bool, Tuple[dict, int]]:
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE":
        return False, ({"error": "VirusTotal API key is not configured on the server."}, 500)
    return True, ({}, 200)


def _to_int(value: Optional[Any]) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def build_summary_text(entity_type: str, vt_payload: Dict[str, Any]) -> Optional[str]:
    if not vt_payload:
        return None
    data = vt_payload.get("data") or {}
    attributes = data.get("attributes") or {}
    normalized_type = "file" if entity_type in {"file", "hash"} else entity_type

    def format_stats(stats: Dict[str, Any]) -> Optional[str]:
        malicious = _to_int(stats.get("malicious"))
        suspicious = _to_int(stats.get("suspicious"))
        harmless = _to_int(stats.get("harmless"))
        undetected = _to_int(stats.get("undetected"))
        total = malicious + suspicious + harmless + undetected
        if total <= 0:
            return None
        if malicious > 0:
            return f"{malicious}/{total} security vendors flagged this object as malicious."
        if suspicious > 0:
            return f"{suspicious}/{total} security vendors flagged this object as suspicious."
        return "No security vendors flagged this object as malicious."

    if normalized_type == "file":
        stats = attributes.get("results_summary", {}).get("stats") or attributes.get("last_analysis_stats")
        return format_stats(stats) if stats else None

    if normalized_type == "url":
        stats = attributes.get("last_analysis_stats")
        summary = format_stats(stats) if stats else None
        if summary:
            return summary
        categories = attributes.get("categories") or {}
        malicious_vendors = [
            verdict for verdict in categories.values()
            if verdict and "malicious" in verdict.lower()
        ]
        if malicious_vendors:
            return f"{len(malicious_vendors)} sources flagged this URL as containing malicious content."
        return "No sources have flagged this URL as malicious."

    if normalized_type in {"domain", "ip_address"}:
        stats = attributes.get("last_analysis_stats")
        if stats:
            return format_stats(stats)

    return None


def _parse_bool(value: Optional[Any]) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "y", "on"}


def _normalize_tags(raw_tags: Any, limit: int = 6) -> List[str]:
    if raw_tags is None:
        return []
    if isinstance(raw_tags, str):
        candidates = [part.strip() for part in raw_tags.split(",")]
    elif isinstance(raw_tags, (list, tuple, set)):
        candidates = [str(item).strip() for item in raw_tags]
    else:
        return []
    normalized: List[str] = []
    seen = set()
    for tag in candidates:
        if not tag:
            continue
        clean = tag[:32].lower()
        if clean in seen:
            continue
        seen.add(clean)
        normalized.append(clean)
        if len(normalized) >= limit:
            break
    return normalized


def _to_isoformat(value: Optional[Any]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    try:
        return datetime.fromisoformat(str(value)).isoformat()
    except (ValueError, TypeError):
        return str(value)


def serialize_category(category: CommunityCategory, post_count: int = 0) -> Dict[str, Any]:
    return {
        "id": category.id,
        "slug": category.slug,
        "name": category.name,
        "description": category.description,
        "display_order": category.display_order,
        "post_count": post_count,
    }


def _coerce_tags(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass
        return [part.strip() for part in stripped.split(",") if part.strip()]
    return []


def serialize_post(
    post: CommunityPost,
    category: Optional[CommunityCategory] = None,
    category_lookup: Optional[Dict[str, CommunityCategory]] = None,
) -> Dict[str, Any]:
    resolved_category = category
    if resolved_category is None and category_lookup and post.category:
        resolved_category = category_lookup.get(post.category)

    return {
        "id": post.id,
        "title": post.title,
        "summary": post.summary,
        "content": post.content,
        "verified": bool(getattr(post, "is_featured", 0)),
        "tags": _coerce_tags(post.tags),
        "reply_count": getattr(post, "comments_count", 0) or 0,
        "upvotes": getattr(post, "views", 0) or 0,
        "category": serialize_category(resolved_category, post_count=0) if resolved_category else (
            {
                "slug": post.category,
                "name": category_lookup[post.category].name if category_lookup and post.category in category_lookup else post.category,
                "description": None,
                "display_order": None,
                "post_count": 0,
            }
            if post.category else None
        ),
        "author": {
            "alias": getattr(post, "author_name", None) or getattr(post, "author_email", None) or "Ẩn danh",
            "email": getattr(post, "author_email", None),
        },
        "timestamps": {
            "created_at": _to_isoformat(post.created_at),
            "updated_at": _to_isoformat(post.updated_at),
        },
    }


def serialize_comment(comment: CommunityComment) -> Dict[str, Any]:
    return {
        "id": comment.id,
        "post_id": comment.post_id,
        "content": comment.content,
        "author": {
            "alias": comment.author_name or comment.author_email,
            "email": comment.author_email,
        },
        "timestamps": {
            "created_at": _to_isoformat(comment.created_at),
        },
    }


def extract_stats(vt_payload: Dict[str, Any]) -> Dict[str, int]:
    attributes = (vt_payload or {}).get("data", {}).get("attributes", {}) or {}
    stats = attributes.get("results_summary", {}).get("stats") or attributes.get("last_analysis_stats") or {}
    return {
        "malicious": _to_int(stats.get("malicious")),
        "suspicious": _to_int(stats.get("suspicious")),
        "harmless": _to_int(stats.get("harmless")),
        "undetected": _to_int(stats.get("undetected")),
    }


def get_or_create_user(session, email: Optional[str], full_name: Optional[str] = None) -> Optional[User]:
    if not email:
        return None
    normalized = email.strip().lower()
    if not normalized:
        return None

    existing = session.execute(
        select(User).where(User.email == normalized)
    ).scalar_one_or_none()

    if existing:
        if full_name and not existing.full_name:
            existing.full_name = full_name
            session.commit()
        return existing

    user = User(email=normalized, full_name=full_name or normalized, password_hash="")
    session.add(user)
    session.commit()
    session.refresh(user)

    # Create empty profile placeholder for future use.
    profile = UserProfile(
        user_id=user.id,
        display_name=full_name or normalized,
        organization="",
        job_title="",
        phone_number="",
        bio="",
    )
    session.add(profile)
    session.commit()
    return user


def persist_completed_scan(
    session,
    *,
    user: Optional[User],
    indicator_type: str,
    indicator_value: str,
    display_value: Optional[str],
    vt_payload: Dict[str, Any],
    vt_analysis_id: Optional[str],
) -> None:
    stats = extract_stats(vt_payload)
    summary = build_summary_text(indicator_type, vt_payload)
    scan = ScanRequest(
        user_id=user.id if user else None,
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        display_value=display_value or indicator_value,
        vt_analysis_id=vt_analysis_id,
        status="completed",
        summary=summary,
        malicious=stats["malicious"],
        suspicious=stats["suspicious"],
        harmless=stats["harmless"],
        undetected=stats["undetected"],
        created_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    vt_status = (vt_payload.get("data") or {}).get("attributes", {}).get("status")
    vt_record = VTResponse(
        scan_id=scan.id,
        vt_status=vt_status,
        raw_payload=vt_payload,
    )
    session.add(vt_record)
    session.commit()


def persist_pending_scan(
    session,
    *,
    user: Optional[User],
    indicator_type: str,
    indicator_value: str,
    display_value: Optional[str],
    vt_analysis_id: str,
) -> ScanRequest:
    scan = ScanRequest(
        user_id=user.id if user else None,
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        display_value=display_value or indicator_value,
        vt_analysis_id=vt_analysis_id,
        status="queued",
        created_at=datetime.utcnow(),
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def update_scan_with_vt_payload(session, vt_analysis_id: str, vt_payload: Dict[str, Any]) -> None:
    scan = session.execute(
        select(ScanRequest).where(ScanRequest.vt_analysis_id == vt_analysis_id)
    ).scalar_one_or_none()

    stats = extract_stats(vt_payload)
    summary = build_summary_text(scan.indicator_type if scan else "file", vt_payload)
    vt_status = (vt_payload.get("data") or {}).get("attributes", {}).get("status")

    if scan:
        scan.summary = summary
        scan.malicious = stats["malicious"]
        scan.suspicious = stats["suspicious"]
        scan.harmless = stats["harmless"]
        scan.undetected = stats["undetected"]
        scan.status = "completed" if vt_status == "completed" else vt_status or "completed"
        scan.completed_at = datetime.utcnow()
        session.commit()

        vt_record = VTResponse(
            scan_id=scan.id,
            vt_status=vt_status,
            raw_payload=vt_payload,
        )
        session.add(vt_record)
        session.commit()
    else:
        # Create ad-hoc record if we did not persist the initial request.
        persist_completed_scan(
            session,
            user=None,
            indicator_type="file",
            indicator_value=vt_analysis_id,
            display_value=vt_analysis_id,
            vt_payload=vt_payload,
            vt_analysis_id=vt_analysis_id,
        )
# Helper function for VirusTotal's URL identifier format


@app.route("/api/community/categories", methods=["GET"])
def list_community_categories():
    session = get_db_session()
    stmt = (
        select(
            CommunityCategory,
            func.count(CommunityPost.id).label("post_count"),
        )
        .outerjoin(CommunityPost, CommunityPost.category == CommunityCategory.slug)
        .where(CommunityCategory.is_active.is_(True))
        .where(or_(CommunityPost.status == "published", CommunityPost.status.is_(None)))
        .group_by(CommunityCategory.id)
        .order_by(asc(CommunityCategory.display_order), asc(CommunityCategory.name))
    )
    categories = [
        serialize_category(category, int(post_count or 0))
        for category, post_count in session.execute(stmt).all()
    ]
    return jsonify({"categories": categories})


@app.route("/api/community/posts", methods=["GET", "POST"])
def community_posts():
    session = get_db_session()

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        title = (payload.get("title") or "").strip()
        summary = (payload.get("summary") or payload.get("description") or "").strip()
        content = (payload.get("content") or "").strip()
        category_slug = (payload.get("category") or payload.get("category_slug") or "").strip().lower()
        tags = _normalize_tags(payload.get("tags"))
        alias = (payload.get("alias") or payload.get("author_alias") or "Chuyên gia ẩn danh").strip()
        author_email = (payload.get("email") or payload.get("author_email") or "").strip()

        if not title or len(title) < 6:
            return jsonify({"error": "Tiêu đề phải có ít nhất 6 ký tự."}), 400
        if len(title) > 255:
            return jsonify({"error": "Tiêu đề quá dài (tối đa 255 ký tự)."}), 400

        if not summary:
            summary = content[:320].strip()
        if not summary:
            return jsonify({"error": "Vui lòng cung cấp mô tả hoặc nội dung ngắn gọn cho bài viết."}), 400

        if len(summary) > 512:
            summary = summary[:512].rstrip() + "…"

        category = None
        if category_slug:
            category = session.execute(
                select(CommunityCategory).where(CommunityCategory.slug == category_slug)
            ).scalar_one_or_none()
            if not category:
                return jsonify({"error": "Danh mục không hợp lệ."}), 400

        fallback_email = "anonymous@community.local"
        normalized_email = (author_email or fallback_email).lower()
        normalized_content = content or summary
        if not normalized_content:
            normalized_content = summary

        post = CommunityPost(
            category=category.slug if category else None,
            title=title,
            summary=summary,
            content=normalized_content,
            tags=tags,
            author_name=alias[:191] if alias else "Chuyên gia ẩn danh",
            author_email=normalized_email[:191],
            status="published",
            is_featured=0,
            views=0,
            comments_count=0,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        session.add(post)
        session.commit()
        session.refresh(post)

        app.logger.info(
            "New community post created id=%s title=%s category=%s tags=%s",
            post.id,
            _truncate(post.title, limit=60),
            category.slug if category else "none",
            ", ".join(_coerce_tags(post.tags)),
        )

        category_map = {category.slug: category} if category else {}
        return jsonify({"post": serialize_post(post, category, category_map)}), 201

    # Handle GET requests
    page_raw = request.args.get("page", 1)
    limit_raw = request.args.get("limit", 10)
    search_term = (request.args.get("q") or request.args.get("query") or "").strip()
    category_slug = (request.args.get("category") or request.args.get("category_slug") or "").strip().lower()
    verified_only = _parse_bool(request.args.get("verified_only"))
    sort_key = (request.args.get("sort") or "newest").strip().lower()

    try:
        page = max(int(page_raw), 1)
    except (TypeError, ValueError):
        page = 1
    try:
        limit = min(max(int(limit_raw), 1), 50)
    except (TypeError, ValueError):
        limit = 10

    offset = (page - 1) * limit

    filters = [CommunityPost.status == "published"]
    if verified_only:
        filters.append(CommunityPost.is_featured.is_(True))
    if category_slug:
        filters.append(CommunityPost.category == category_slug)
    if search_term:
        keyword = f"%{search_term.lower()}%"
        filters.append(
            or_(
                func.lower(CommunityPost.title).like(keyword),
                func.lower(CommunityPost.summary).like(keyword),
            )
        )

    order_mapping = {
        "newest": [desc(CommunityPost.created_at)],
        "popular": [desc(CommunityPost.views), desc(CommunityPost.comments_count)],
        "active": [desc(CommunityPost.updated_at)],
    }
    order_clause = order_mapping.get(sort_key, order_mapping["newest"])

    base_stmt = (
        select(CommunityPost, CommunityCategory)
        .outerjoin(CommunityCategory, CommunityPost.category == CommunityCategory.slug)
    )
    if filters:
        base_stmt = base_stmt.where(*filters)

    stmt = base_stmt.order_by(*order_clause).limit(limit).offset(offset)
    rows = session.execute(stmt).all()

    count_stmt = (
        select(func.count(CommunityPost.id))
        .outerjoin(CommunityCategory, CommunityPost.category == CommunityCategory.slug)
    )
    if filters:
        count_stmt = count_stmt.where(*filters)
    total = session.execute(count_stmt).scalar_one()

    category_lookup = {
        slug: category_obj
        for slug, category_obj in session.execute(
            select(CommunityCategory.slug, CommunityCategory).where(CommunityCategory.is_active.is_(True))
        ).all()
    }
    posts = [serialize_post(post, category, category_lookup) for post, category in rows]

    return jsonify(
        {
            "posts": posts,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": int(total or 0),
                "has_next": (page * limit) < (total or 0),
            },
        }
    )


@app.route("/api/community/posts/<int:post_id>", methods=["GET"])
def get_community_post(post_id: int):
    session = get_db_session()
    post = session.execute(
        select(CommunityPost).where(CommunityPost.id == post_id)
    ).scalar_one_or_none()
    if not post or post.status != "published":
        return jsonify({"error": "Không tìm thấy bài viết."}), 404

    if post.views is None:
        post.views = 0
    post.views += 1
    post.updated_at = datetime.utcnow()
    session.commit()
    session.refresh(post)

    category = None
    if post.category:
        category = session.execute(
            select(CommunityCategory).where(CommunityCategory.slug == post.category)
        ).scalar_one_or_none()

    comments = session.execute(
        select(CommunityComment)
        .where(CommunityComment.post_id == post.id)
        .order_by(asc(CommunityComment.created_at))
    ).scalars().all()

    return jsonify(
        {
            "post": serialize_post(post, category),
            "comments": [serialize_comment(comment) for comment in comments],
        }
    )


@app.route("/api/community/posts/<int:post_id>/comments", methods=["POST"])
def create_community_comment(post_id: int):
    session = get_db_session()
    post = session.execute(
        select(CommunityPost).where(CommunityPost.id == post_id)
    ).scalar_one_or_none()
    if not post or post.status != "published":
        return jsonify({"error": "Không tìm thấy bài viết."}), 404

    payload = request.get_json(silent=True) or {}
    content = (payload.get("content") or "").strip()
    alias = (payload.get("alias") or payload.get("author_name") or "Ẩn danh").strip()
    author_email = (payload.get("email") or payload.get("author_email") or "").strip()

    if len(content) < 4:
        return jsonify({"error": "Bình luận cần ít nhất 4 ký tự."}), 400
    if len(content) > 4000:
        return jsonify({"error": "Bình luận quá dài (tối đa 4000 ký tự)."}), 400

    fallback_email = "anonymous@community.local"
    normalized_email = (author_email or fallback_email)[:191]
    normalized_alias = alias[:191] if alias else None

    comment = CommunityComment(
        post_id=post.id,
        author_email=normalized_email,
        author_name=normalized_alias,
        content=content,
        created_at=datetime.utcnow(),
    )
    session.add(comment)
    post.comments_count = (post.comments_count or 0) + 1
    post.updated_at = datetime.utcnow()
    session.commit()
    session.refresh(comment)
    session.refresh(post)

    category = None
    if post.category:
        category = session.execute(
            select(CommunityCategory).where(CommunityCategory.slug == post.category)
        ).scalar_one_or_none()

    return (
        jsonify(
            {
                "comment": serialize_comment(comment),
                "post": serialize_post(post, category),
            }
        ),
        201,
    )


@app.route("/api/community/posts/<int:post_id>/verify", methods=["POST"])
def verify_community_post(post_id: int):
    if not COMMUNITY_MODERATOR_TOKEN:
        return jsonify({"error": "Chưa cấu hình mã xác thực moderator trên máy chủ."}), 503

    payload = request.get_json(silent=True) or {}
    provided_token = (request.headers.get("X-Moderator-Token") or payload.get("token") or "").strip()
    if not provided_token or provided_token != COMMUNITY_MODERATOR_TOKEN:
        return jsonify({"error": "Mã xác thực moderator không hợp lệ."}), 403

    session = get_db_session()
    post = session.execute(
        select(CommunityPost).where(CommunityPost.id == post_id)
    ).scalar_one_or_none()
    if not post:
        return jsonify({"error": "Không tìm thấy bài viết."}), 404

    desired_state = _parse_bool(payload.get("verified", True))
    post.is_featured = 1 if desired_state else 0
    post.updated_at = datetime.utcnow()
    session.commit()
    session.refresh(post)

    app.logger.info("Post %s verification toggled -> %s", post.id, bool(post.is_featured))

    return jsonify({"post": serialize_post(post)})


# Helper function for VirusTotal's URL identifier format
def get_vt_url_identifier(url):
    """Creates a URL identifier for the VirusTotal API by base64-encoding it.
    See: https://developers.virustotal.com/reference/url
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


@app.route("/")
def index():
    app.logger.debug("Health check ping from %s", request.remote_addr)
    return "Ransomware Threat Intelligence Portal Backend is running!"


@app.route("/api/analyze", methods=["POST"])
def analyze():
    ok, payload = ensure_api_key()
    if not ok:
        return jsonify(payload[0]), payload[1]

    data = request.get_json() or {}
    indicator_type = data.get("type")
    indicator_value = (data.get("value") or "").strip()
    user_email = (data.get("user_email") or "").strip()
    user_full_name = (data.get("user_full_name") or data.get("user_display_name") or "").strip()
    display_value = (data.get("display_value") or indicator_value).strip()

    if not all([indicator_type, indicator_value]):
        return jsonify({"error": "Missing indicator type or value"}), 400

    # Validate input
    is_valid, error_msg = validate_indicator(indicator_type, indicator_value)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    # Map frontend types to VirusTotal API endpoints
    endpoint_map = {
        "file": f"files/{indicator_value}",
        "url": f"urls/{get_vt_url_identifier(indicator_value)}",
        "domain": f"domains/{indicator_value}",
        "ip_address": f"ip_addresses/{indicator_value}",
    }

    endpoint = endpoint_map.get(indicator_type)
    if not endpoint:
        return jsonify({"error": "Invalid indicator type specified"}), 400

    app.logger.info(
        "Lookup request: type=%s indicator=%s user=%s",
        indicator_type,
        _truncate(indicator_value),
        user_email or "anonymous",
    )

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_response = requests.get(f"{VT_API_URL}/{endpoint}", headers=headers, timeout=DEFAULT_TIMEOUT)
        vt_response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        vt_payload = vt_response.json()

        # Persist scan result if user info is available.
        if user_email:
            session = get_db_session()
            try:
                user = get_or_create_user(session, user_email, user_full_name or None)
                persist_completed_scan(
                    session,
                    user=user,
                    indicator_type=indicator_type,
                    indicator_value=indicator_value,
                    display_value=display_value or indicator_value,
                    vt_payload=vt_payload,
                    vt_analysis_id=(vt_payload.get("data") or {}).get("id"),
                )
            except SQLAlchemyError:
                app.logger.exception("Failed to persist scan result for %s", user_email)
                session.rollback()
        return jsonify(vt_payload), vt_response.status_code

    except requests.exceptions.HTTPError as e:
        # Forward the error from VirusTotal API to the client
        try:
            return jsonify(e.response.json()), e.response.status_code
        except Exception:  # pragma: no cover - fallback for non-JSON responses
            return jsonify({"error": e.response.text}), e.response.status_code
    except requests.exceptions.RequestException as e:
        # Handle network errors or other request issues
        return jsonify({"error": f"Failed to connect to VirusTotal API: {e}"}), 503
    except Exception as e:  # pragma: no cover - defensive
        return jsonify({"error": f"An unexpected server error occurred: {e}"}), 500


@app.route("/api/upload-file", methods=["POST"])
def upload_file():
    ok, payload = ensure_api_key()
    if not ok:
        return jsonify(payload[0]), payload[1]

    user_email = (request.form.get("user_email") or "").strip()
    user_full_name = (request.form.get("user_full_name") or request.form.get("user_display_name") or "").strip()

    file = request.files.get("file")
    if not file or file.filename == "":
        return jsonify({"error": "Missing file upload"}), 400

    # Sanitize filename
    safe_filename = sanitize_filename(file.filename)

    # Determine file size and hash
    file.stream.seek(0)
    file_bytes = file.stream.read()
    file_size = len(file_bytes)
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    if file_size > VT_MAX_FILE_SIZE:
        return (
            jsonify(
                {
                    "error": "File exceeds VirusTotal size limit",
                    "details": f"Received {round(file_size / (1024 * 1024), 2)} MB, limit is 32 MB for public API.",
                }
            ),
            400,
        )

    app.logger.info(
        "File upload received: name=%s size=%d bytes user=%s",
        safe_filename,
        file_size,
        user_email or "anonymous",
    )

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    file_buffer = io.BytesIO(file_bytes)
    files = {
        "file": (safe_filename, file_buffer, file.mimetype or "application/octet-stream"),
    }

    session = None
    user = None
    if user_email:
        session = get_db_session()
        try:
            user = get_or_create_user(session, user_email, user_full_name or None)
        except SQLAlchemyError:
            if session is not None:
                session.rollback()
            app.logger.exception("Failed to ensure user %s before persisting scan", user_email)
            user = None

    try:
        vt_response = requests.post(
            f"{VT_API_URL}/files", headers=headers, files=files, timeout=DEFAULT_TIMEOUT
        )
        vt_response.raise_for_status()
        vt_json = vt_response.json()
        analysis_id = vt_json.get("data", {}).get("id")

        # Persist queued scan for later update.
        if analysis_id and user_email and session is not None:
            try:
                persist_pending_scan(
                    session,
                    user=user,
                    indicator_type="file",
                    indicator_value=file_hash,
                    display_value=safe_filename,
                    vt_analysis_id=analysis_id,
                )
            except SQLAlchemyError:
                session.rollback()
                app.logger.exception("Failed to record pending scan for analysis %s", analysis_id)

        return (
            jsonify(
                {
                    "analysis_id": analysis_id,
                    "vt_response": vt_json,
                }
            ),
            200,
        )
    except requests.exceptions.HTTPError as e:
        try:
            return jsonify(e.response.json()), e.response.status_code
        except Exception:
            return jsonify({"error": e.response.text}), e.response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to upload file to VirusTotal: {e}"}), 503
    except Exception as e:
        return jsonify({"error": f"Unexpected server error: {e}"}), 500


@app.route("/api/upload-url", methods=["POST"])
def upload_url():
    ok, payload = ensure_api_key()
    if not ok:
        return jsonify(payload[0]), payload[1]

    data = request.get_json() or {}
    url_value = (data.get("url") or "").strip()
    user_email = (data.get("user_email") or "").strip()
    user_full_name = (data.get("user_full_name") or data.get("user_display_name") or "").strip()
    if not url_value:
        return jsonify({"error": "Missing URL value"}), 400

    # Validate URL
    is_valid, error_msg = validate_indicator('url', url_value)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    app.logger.info(
        "URL submission received: %s (user=%s)",
        _truncate(url_value),
        user_email or "anonymous",
    )
    # VirusTotal expects form-encoded data for URL submissions
    try:
        vt_response = requests.post(
            f"{VT_API_URL}/urls", headers=headers, data={"url": url_value}, timeout=DEFAULT_TIMEOUT
        )
        vt_response.raise_for_status()
        vt_json = vt_response.json()
        analysis_id = vt_json.get("data", {}).get("id")

        if analysis_id and user_email:
            session = get_db_session()
            try:
                user = get_or_create_user(session, user_email, user_full_name or None)
                persist_pending_scan(
                    session,
                    user=user,
                    indicator_type="url",
                    indicator_value=url_value,
                    display_value=url_value,
                    vt_analysis_id=analysis_id,
                )
            except SQLAlchemyError:
                session.rollback()
                app.logger.exception("Failed to record pending URL scan for %s", url_value)

        return jsonify({"analysis_id": analysis_id, "vt_response": vt_json}), 200
    except requests.exceptions.HTTPError as e:
        try:
            return jsonify(e.response.json()), e.response.status_code
        except Exception:
            return jsonify({"error": e.response.text}), e.response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to submit URL to VirusTotal: {e}"}), 503
    except Exception as e:
        return jsonify({"error": f"Unexpected server error: {e}"}), 500


@app.route("/api/analysis/<analysis_id>", methods=["GET"])
def fetch_analysis(analysis_id):
    ok, payload = ensure_api_key()
    if not ok:
        return jsonify(payload[0]), payload[1]

    if not analysis_id:
        return jsonify({"error": "Missing analysis ID"}), 400

    app.logger.info("Polling analysis status for %s", _truncate(analysis_id))

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        vt_response = requests.get(
            f"{VT_API_URL}/analyses/{analysis_id}", headers=headers, timeout=DEFAULT_TIMEOUT
        )
        vt_response.raise_for_status()
        vt_payload = vt_response.json()

        attributes = (vt_payload.get("data") or {}).get("attributes") or {}
        vt_status = attributes.get("status")
        if vt_status == "completed":
            session = get_db_session()
            try:
                update_scan_with_vt_payload(session, analysis_id, vt_payload)
            except SQLAlchemyError:
                session.rollback()
                app.logger.exception("Failed to update scan result for %s", analysis_id)

        return jsonify(vt_payload), vt_response.status_code
    except requests.exceptions.HTTPError as e:
        try:
            return jsonify(e.response.json()), e.response.status_code
        except Exception:
            return jsonify({"error": e.response.text}), e.response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to fetch analysis from VirusTotal: {e}"}), 503
    except Exception as e:
        return jsonify({"error": f"Unexpected server error: {e}"}), 500


def serialize_scan(scan: ScanRequest) -> Dict[str, Any]:
    total = (scan.malicious or 0) + (scan.suspicious or 0) + (scan.harmless or 0) + (scan.undetected or 0)
    latest_response = scan.vt_responses[-1].raw_payload if scan.vt_responses else None
    return {
        "id": scan.id,
        "indicator": scan.indicator_value,
        "display": scan.display_value,
        "type": scan.indicator_type,
        "summary": scan.summary,
        "malicious": scan.malicious or 0,
        "suspicious": scan.suspicious or 0,
        "harmless": scan.harmless or 0,
        "undetected": scan.undetected or 0,
        "total": total,
        "status": scan.status,
        "savedAt": (scan.completed_at or scan.created_at or datetime.utcnow()).isoformat(),
        "vtAnalysisId": scan.vt_analysis_id,
        "response": latest_response,
    }


@app.route("/api/history", methods=["GET", "DELETE"])
def history():
    email = (request.args.get("email") or request.args.get("user_email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Missing email parameter"}), 400

    app.logger.info("History %s request for %s", request.method, email)

    session = get_db_session()
    user = session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        return jsonify({"history": []}) if request.method == "GET" else jsonify({"deleted": 0})

    if request.method == "DELETE":
        try:
            result = session.execute(delete(ScanRequest).where(ScanRequest.user_id == user.id))
            session.commit()
            return jsonify({"deleted": result.rowcount or 0})
        except SQLAlchemyError:
            session.rollback()
            app.logger.exception("Failed to clear history for %s", email)
            return jsonify({"error": "Failed to clear history"}), 500

    # GET
    limit = request.args.get("limit", "100")
    try:
        limit_int = max(1, min(int(limit), 200))
    except ValueError:
        limit_int = 100

    scans = session.execute(
        select(ScanRequest)
        .where(ScanRequest.user_id == user.id)
        .order_by(ScanRequest.created_at.desc())
        .limit(limit_int)
    ).scalars().all()

    return jsonify({"history": [serialize_scan(scan) for scan in scans]})


if __name__ == "__main__":
    # Port 5001 is used to avoid conflict with other services.
    app.run(debug=True, port=5001)
