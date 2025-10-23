import os
import io
import base64
import hashlib
from datetime import datetime
from typing import Tuple, Optional, Dict, Any

import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError

from validators import validate_indicator, sanitize_filename
from database import get_session, init_database
from models import (
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

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_API_URL = "https://www.virustotal.com/api/v3"
VT_MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB limit for public API
DEFAULT_TIMEOUT = (10, 120)  # (connect, read) timeouts for VT requests

# Ensure database schema is available.
init_database()


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
def get_vt_url_identifier(url):
    """Creates a URL identifier for the VirusTotal API by base64-encoding it.
    See: https://developers.virustotal.com/reference/url
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


@app.route("/")
def index():
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
            except SQLAlchemyError as exc:
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

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    file_buffer = io.BytesIO(file_bytes)
    files = {
        "file": (safe_filename, file_buffer, file.mimetype or "application/octet-stream"),
    }

    session = get_db_session()
    user = None
    if user_email:
        try:
            user = get_or_create_user(session, user_email, user_full_name or None)
        except SQLAlchemyError:
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
        if analysis_id and user_email:
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
