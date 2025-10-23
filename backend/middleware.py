"""
Rate limiting and security middleware for Flask app
"""
from functools import wraps
from flask import request, jsonify
from collections import defaultdict
from datetime import datetime, timedelta
import threading

# In-memory storage for rate limiting (use Redis in production)
request_counts = defaultdict(lambda: {'count': 0, 'reset_time': None})
request_lock = threading.Lock()

# Configuration
RATE_LIMIT_REQUESTS = 100  # requests per window
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds
RATE_LIMIT_STRICT = 10  # for sensitive endpoints (login, register)
RATE_LIMIT_STRICT_WINDOW = 300  # 5 minutes


def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


def rate_limit(max_requests=RATE_LIMIT_REQUESTS, window=RATE_LIMIT_WINDOW):
    """
    Rate limiting decorator
    Usage: @rate_limit(max_requests=10, window=60)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()
            now = datetime.now()
            
            with request_lock:
                client_data = request_counts[client_ip]
                
                # Reset counter if window expired
                if client_data['reset_time'] is None or now > client_data['reset_time']:
                    client_data['count'] = 0
                    client_data['reset_time'] = now + timedelta(seconds=window)
                
                # Check limit
                if client_data['count'] >= max_requests:
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'message': 'Too many requests. Please try again later.',
                        'retry_after': int((client_data['reset_time'] - now).total_seconds())
                    }), 429
                
                # Increment counter
                client_data['count'] += 1
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_content_type(content_type='application/json'):
    """
    Ensure request has correct Content-Type
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'PATCH']:
                if 'multipart/form-data' not in request.content_type:
                    if request.content_type != content_type:
                        return jsonify({
                            'error': 'Invalid Content-Type',
                            'expected': content_type,
                            'received': request.content_type
                        }), 415
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def sanitize_headers():
    """Add security headers to response"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            
            # Convert response to Response object if needed
            from flask import make_response
            if not hasattr(response, 'headers'):
                response = make_response(response)
            
            # Add security headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            
            return response
        return decorated_function
    return decorator


def cleanup_rate_limits():
    """
    Cleanup expired rate limit entries (call periodically)
    """
    now = datetime.now()
    with request_lock:
        expired_ips = [
            ip for ip, data in request_counts.items()
            if data['reset_time'] and now > data['reset_time'] + timedelta(hours=24)
        ]
        for ip in expired_ips:
            del request_counts[ip]


# API Key validation (additional layer)
def require_api_key_header():
    """
    Require custom API key in header (for additional security)
    This is different from VirusTotal API key
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            # In production, validate against database
            # For now, just check if present
            if not api_key:
                return jsonify({
                    'error': 'Missing API key',
                    'message': 'X-API-Key header is required'
                }), 401
            return f(*args, **kwargs)
        return decorated_function
    return decorator
