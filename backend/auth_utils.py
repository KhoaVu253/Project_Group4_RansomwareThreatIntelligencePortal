"""
Authentication utilities for JWT token management
"""
import os
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict
from flask import g

JWT_SECRET = os.getenv('JWT_SECRET_KEY', 'change-this-in-production-secret-key')
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRY = timedelta(hours=1)  # 1 hour


def generate_access_token(user_id: int, email: str) -> str:
    """Generate JWT access token"""
    payload = {
        'user_id': user_id,
        'email': email,
        'type': 'access',
        'exp': datetime.utcnow() + ACCESS_TOKEN_EXPIRY,
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> Optional[Dict]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None



























