"""
Two-Factor Authentication service using TOTP (Google Authenticator compatible)
"""
import pyotp
import qrcode
import io
import base64
import secrets
from typing import Tuple, List, Optional


def generate_totp_secret() -> str:
    """Generate TOTP secret for Google Authenticator"""
    return pyotp.random_base32()


def generate_qr_code(secret: str, email: str, app_name: str = "VirusTotal Intelligence") -> str:
    """Generate QR code for TOTP setup"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=app_name
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    img_base64 = base64.b64encode(buffer.read()).decode()
    return f"data:image/png;base64,{img_base64}"


def verify_totp(secret: str, token: str) -> bool:
    """Verify TOTP token from Google Authenticator"""
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)  # Allow 1 step tolerance (30 seconds)


def generate_backup_codes(count: int = 10) -> List[str]:
    """Generate backup codes for 2FA"""
    return [secrets.token_hex(4).upper() for _ in range(count)]



























