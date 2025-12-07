import os
import logging
import requests
from typing import Dict, Any
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Ensure environment variables from .env are loaded when module is imported
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-exp")
GEMINI_ENDPOINT = os.getenv("GEMINI_ENDPOINT", "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent")


def _build_analysis_prompt(vt_data: Dict[str, Any], indicator_type: str, indicator_value: str) -> str:
    """Xây dựng prompt chi tiết cho Gemini từ kết quả VirusTotal"""
    attributes = (vt_data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {})
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    
    # Lấy top detections
    top_detections = []
    for engine, result in list(results.items())[:10]:  # Top 10
        if result.get("category") in ["malicious", "suspicious"]:
            top_detections.append(f"- {engine}: {result.get('result', 'N/A')} ({result.get('category')})")
    
    # Lấy thông tin file nếu có
    file_info = attributes.get("file_info") or {}
    file_name = file_info.get("name") or indicator_value
    file_size = file_info.get("size")
    file_type = file_info.get("type_description") or file_info.get("type_tag")
    
    prompt = f"""Bạn là một chuyên gia phân tích bảo mật (Security Analyst). Dựa trên kết quả quét từ trang kết quả, hãy đưa ra phân tích chi tiết và khuyến nghị.

THÔNG TIN QUÉT:
- Loại chỉ báo: {indicator_type}
- Giá trị: {indicator_value}
- Tên file: {file_name if file_name != indicator_value else 'N/A'}
- Kích thước: {file_size} bytes (nếu có)
- Loại file: {file_type or 'N/A'}
- Tổng số engine quét: {total}
- Phát hiện độc hại: {malicious}
- Phát hiện đáng ngờ: {suspicious}
- An toàn: {harmless}
- Chưa phát hiện: {undetected}

CÁC PHÁT HIỆN CHÍNH:
{chr(10).join(top_detections) if top_detections else "Không có phát hiện đáng ngờ"}

YÊU CẦU PHÂN TÍCH:
1. Đánh giá mức độ rủi ro (Nguy hiểm/Cảnh báo/An toàn/Không xác định) dựa trên số lượng engine phát hiện
2. Phân tích chi tiết các phát hiện từ các engine - giải thích ý nghĩa của các detection names
3. Đưa ra 3-5 khuyến nghị cụ thể và hành động cho người dùng (ví dụ: xóa file, cách ly, quét lại, v.v.)
4. Giải thích ngắn gọn về các mối đe dọa tiềm ẩn nếu có
5. Đưa ra lời khuyên về cách xử lý tiếp theo
6. Tổng hợp những dữ liệu vừa phân tích đưa ra một kết luận đầy đủ về mức độ nguy hiểm của chỉ báo này

Hãy trả lời bằng tiếng Việt, ngắn gọn, dễ hiểu và tập trung vào hành động thực tế. Format output với các section rõ ràng."""

    return prompt


def generate_gemini_analysis(vt_data: Dict[str, Any], indicator_type: str, indicator_value: str, timeout: int = 15) -> Dict[str, Any]:
    """Gọi Gemini API để phân tích kết quả VirusTotal"""
    
    if not GEMINI_API_KEY:
        return {"error": "Gemini API chưa được cấu hình"}
    
    prompt = _build_analysis_prompt(vt_data, indicator_type, indicator_value)
    
    # Gemini API format
    url = GEMINI_ENDPOINT.format(model=GEMINI_MODEL)
    params = {"key": GEMINI_API_KEY}
    
    payload = {
        "contents": [{
            "parts": [{
                "text": prompt
            }]
        }],
        "generationConfig": {
            "temperature": 0.7,
            "topK": 40,
            "topP": 0.95,
            "maxOutputTokens": 1024,
        }
    }
    
    try:
        resp = requests.post(url, params=params, json=payload, timeout=timeout)
        
        # Xử lý các HTTP status codes cụ thể
        if resp.status_code == 429:
            logger.warning(f"Gemini API rate limit exceeded (429) for indicator: {indicator_value[:50]}")
            return {
                "error": "Gemini API đã vượt quá giới hạn request. Vui lòng đợi vài phút rồi thử lại.",
                "error_code": "RATE_LIMIT_EXCEEDED",
                "retry_after": 60  # seconds
            }
        
        if resp.status_code == 400:
            error_data = resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {}
            error_msg = error_data.get('error', {}).get('message', 'Invalid request to Gemini API')
            logger.error(f"Gemini API bad request (400): {error_msg}")
            return {
                "error": f"Lỗi yêu cầu đến Gemini API: {error_msg}",
                "error_code": "BAD_REQUEST"
            }
        
        if resp.status_code == 401:
            logger.error("Gemini API authentication failed (401)")
            return {
                "error": "Gemini API key không hợp lệ hoặc đã hết hạn. Vui lòng kiểm tra lại cấu hình.",
                "error_code": "AUTHENTICATION_FAILED"
            }
        
        if resp.status_code == 403:
            logger.error("Gemini API access forbidden (403)")
            return {
                "error": "Không có quyền truy cập Gemini API. Vui lòng kiểm tra API key và quota.",
                "error_code": "ACCESS_FORBIDDEN"
            }
        
        if resp.status_code >= 500:
            logger.error(f"Gemini API server error ({resp.status_code})")
            return {
                "error": f"Lỗi server từ Gemini API (HTTP {resp.status_code}). Vui lòng thử lại sau.",
                "error_code": "SERVER_ERROR"
            }
        
        # Kiểm tra status code thành công
        resp.raise_for_status()
        data = resp.json()
        
        # Parse Gemini response
        candidates = data.get("candidates", [])
        if not candidates:
            logger.warning("Gemini API returned no candidates")
            return {"error": "Gemini không trả về kết quả"}
        
        # Kiểm tra safety ratings
        if candidates[0].get("finishReason") == "SAFETY":
            logger.warning("Gemini API blocked content due to safety concerns")
            return {
                "error": "Nội dung bị chặn bởi Gemini do vấn đề an toàn. Vui lòng thử với file khác.",
                "error_code": "SAFETY_BLOCKED"
            }
        
        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        if not parts:
            logger.warning("Gemini API response has no parts")
            return {"error": "Gemini response không hợp lệ"}
        
        text = parts[0].get("text", "").strip()
        if not text:
            logger.warning("Gemini API returned empty text")
            return {"error": "Gemini response rỗng"}
        
        logger.info(f"Successfully generated Gemini analysis for {indicator_type}: {indicator_value[:50]}")
        return {"analysis": text}
        
    except requests.exceptions.Timeout:
        logger.error(f"Gemini API timeout after {timeout}s")
        return {
            "error": f"Gemini API timeout sau {timeout} giây. Vui lòng thử lại.",
            "error_code": "TIMEOUT"
        }
    except requests.exceptions.HTTPError as exc:
        logger.error(f"Gemini API HTTP error: {exc}")
        return {
            "error": f"Lỗi HTTP từ Gemini API: {exc}",
            "error_code": "HTTP_ERROR"
        }
    except requests.exceptions.ConnectionError as exc:
        logger.error(f"Gemini API connection error: {exc}")
        return {
            "error": "Không thể kết nối đến Gemini API. Vui lòng kiểm tra kết nối internet.",
            "error_code": "CONNECTION_ERROR"
        }
    except requests.exceptions.RequestException as exc:
        logger.error(f"Gemini API request error: {exc}")
        return {
            "error": f"Lỗi kết nối Gemini API: {exc}",
            "error_code": "REQUEST_ERROR"
        }
    except Exception as exc:
        logger.exception(f"Unexpected error in Gemini analysis: {exc}")
        return {
            "error": f"Lỗi không xác định: {exc}",
            "error_code": "UNKNOWN_ERROR"
        }

