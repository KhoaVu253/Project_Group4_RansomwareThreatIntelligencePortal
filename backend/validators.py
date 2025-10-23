"""
Input validation utilities for security
"""
import re
from typing import Tuple, Optional

def validate_hash(value: str) -> Tuple[bool, Optional[str]]:
    """Validate file hash (MD5, SHA1, SHA256)"""
    value = value.strip().lower()
    
    # MD5: 32 hex chars
    if len(value) == 32 and re.match(r'^[a-f0-9]{32}$', value):
        return True, None
    
    # SHA1: 40 hex chars
    if len(value) == 40 and re.match(r'^[a-f0-9]{40}$', value):
        return True, None
    
    # SHA256: 64 hex chars
    if len(value) == 64 and re.match(r'^[a-f0-9]{64}$', value):
        return True, None
    
    return False, "Invalid hash format. Expected MD5, SHA1, or SHA256."


def validate_url(value: str) -> Tuple[bool, Optional[str]]:
    """Validate URL format"""
    value = value.strip()
    
    # Basic URL validation
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(value):
        return False, "Invalid URL format."
    
    # Length check
    if len(value) > 2048:
        return False, "URL too long (max 2048 characters)."
    
    return True, None


def validate_domain(value: str) -> Tuple[bool, Optional[str]]:
    """Validate domain name"""
    value = value.strip().lower()
    
    # Domain validation
    domain_pattern = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
        re.IGNORECASE
    )
    
    if not domain_pattern.match(value):
        return False, "Invalid domain format."
    
    if len(value) > 253:
        return False, "Domain name too long."
    
    return True, None


def validate_ip_address(value: str) -> Tuple[bool, Optional[str]]:
    """Validate IP address (IPv4 and IPv6)"""
    value = value.strip()
    
    # IPv4 validation
    ipv4_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    # IPv6 validation (simplified)
    ipv6_pattern = re.compile(
        r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,7}:|'
        r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
        r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
        r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
        r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
        r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
        r'::(ffff(:0{1,4}){0,1}:){0,1}'
        r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
        r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
        r'([0-9a-fA-F]{1,4}:){1,4}:'
        r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
        r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
    )
    
    if ipv4_pattern.match(value) or ipv6_pattern.match(value):
        return True, None
    
    return False, "Invalid IP address format."


def validate_indicator(indicator_type: str, value: str) -> Tuple[bool, Optional[str]]:
    """Validate indicator based on type"""
    validators = {
        'file': validate_hash,
        'url': validate_url,
        'domain': validate_domain,
        'ip_address': validate_ip_address,
    }
    
    validator = validators.get(indicator_type)
    if not validator:
        return False, f"Unknown indicator type: {indicator_type}"
    
    return validator(value)


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """Sanitize filename to prevent path traversal"""
    # Remove path separators
    filename = filename.replace('/', '_').replace('\\', '_')
    
    # Remove null bytes
    filename = filename.replace('\0', '')
    
    # Limit length
    if len(filename) > max_length:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:max_length - len(ext) - 1] + '.' + ext if ext else name[:max_length]
    
    return filename
