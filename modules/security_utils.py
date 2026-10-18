"""
Security and validation utilities for Digital Fraud & Threat Defense Guard.

Provides:
- Sensitive data masking (OTPs, passwords, credit card numbers, auth tokens, PINs)
- URL sanitization (stripping userinfo and sensitive query parameters)
- File upload validation (magic bytes, size limits, format checks)
"""

from __future__ import annotations

import io
import re
from typing import Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Common sensitive parameter names in query strings
SENSITIVE_QUERY_PARAMS: Set[str] = {
    "token", "access_token", "auth", "key", "api_key", "apikey",
    "password", "pass", "pwd", "secret", "otp", "code", "pin",
    "session", "session_id", "sessionid", "auth_token", "private_key",
}

# Magic numbers for image types
IMAGE_MAGIC_SIGNATURES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "webp": b"RIFF",  # starts with RIFF and has WEBP at offset 8
    "gif": b"GIF8",
    "bmp": b"BM",
}


def mask_sensitive_text(text: Optional[str], max_length: int = 1000) -> str:
    """
    Mask sensitive tokens (OTPs, PINs, card numbers, passwords) and limit length
    before storing in logs or databases.
    """
    if not text:
        return ""

    s = str(text)

    # 1. Mask credit/debit card numbers (13 to 19 digits, possibly separated by spaces or dashes)
    s = re.sub(
        r"\b(?:\d[ -]*?){13,19}\b",
        lambda m: f"[CARD_REDACTED_...{re.sub(r'\D', '', m.group(0))[-4:]}]"
        if len(re.sub(r"\D", "", m.group(0))) >= 12
        else m.group(0),
        s,
    )

    # 2. Mask OTPs / verification codes near context keywords
    s = re.sub(
        r"(?i)\b(otp|code|pin|password|passcode|secret)[\s:=#\-]+(\d{4,8})\b",
        r"\1: [REDACTED_CODE]",
        s,
    )

    # 3. Mask passwords in key-value format (e.g. password: xyz123)
    s = re.sub(
        r"(?i)\b(password|passwd|pwd)[\s:=]+([^\s,;]+)",
        r"\1: [REDACTED_PASSWORD]",
        s,
    )

    # 4. Mask Aadhaar numbers (12 digits, often 4-4-4)
    s = re.sub(
        r"\b\d{4}\s\d{4}\s\d{4}\b",
        "[AADHAAR_REDACTED]",
        s,
    )

    # 5. Mask PAN numbers (5 uppercase letters, 4 digits, 1 letter)
    s = re.sub(
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
        "[PAN_REDACTED]",
        s,
    )

    # Truncate to maximum length safely
    if len(s) > max_length:
        s = s[:max_length] + " [TRUNCATED]"

    return s


def sanitize_url_for_logging(url: str) -> str:
    """
    Strip embedded credentials (user:password@) and redact sensitive query parameters.
    """
    if not url or not isinstance(url, str):
        return ""

    try:
        parsed = urlparse(url)
    except Exception:
        return "[INVALID_URL]"

    # Strip userinfo (user:pass)
    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    # Redact sensitive query params
    if parsed.query:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_pairs = []
        for k, v in query_pairs:
            if k.lower() in SENSITIVE_QUERY_PARAMS:
                sanitized_pairs.append((k, "[REDACTED]"))
            else:
                sanitized_pairs.append((k, v))
        new_query = urlencode(sanitized_pairs)
    else:
        new_query = ""

    sanitized = urlunparse((
        parsed.scheme,
        netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment,
    ))
    return sanitized[:500]


def validate_image_bytes(data: bytes, max_bytes: int = 10 * 1024 * 1024) -> Tuple[bool, str]:
    """
    Validate that raw bytes represent a safe, supported image format within size limits.
    """
    if not data:
        return False, "Image file is empty."

    if len(data) > max_bytes:
        return False, f"Image size ({len(data) / (1024*1024):.1f} MB) exceeds maximum allowed ({max_bytes / (1024*1024):.0f} MB)."

    # Header check
    is_png = data.startswith(IMAGE_MAGIC_SIGNATURES["png"])
    is_jpeg = data.startswith(IMAGE_MAGIC_SIGNATURES["jpeg"])
    is_webp = data.startswith(IMAGE_MAGIC_SIGNATURES["webp"]) and len(data) > 12 and data[8:12] == b"WEBP"
    is_bmp = data.startswith(IMAGE_MAGIC_SIGNATURES["bmp"])

    if not (is_png or is_jpeg or is_webp or is_bmp):
        return False, "Unsupported or invalid image file format. Please upload PNG, JPG, or WEBP."

    return True, "Valid"
