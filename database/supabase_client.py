"""
Supabase connector: securely saves every scan to `scan_history` and fetches recent logs.

Security & Reliability features:
- Automatically detects and ignores placeholder credentials (e.g. your_supabase_anon_key).
- Pre-sanitizes and masks sensitive data (OTPs, card numbers, passwords) prior to logging.
- Maintains an in-memory session log buffer as a fallback when Supabase is not configured
  or unreachable, ensuring the dashboard's History tab remains useful in all environments.
- Fails soft with clear, user-friendly messages rather than raising unhandled exceptions.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from modules.security_utils import mask_sensitive_text

logger = logging.getLogger(__name__)

TABLE = "scan_history"
VALID_TYPES = {"text", "image", "url", "app_audit"}

# In-memory history fallback for local/offline sessions
_local_history: List[Dict[str, Any]] = []
_client = None

# Known placeholder secrets that should not be used
PLACEHOLDER_SECRETS = {
    "https://your-project.supabase.co",
    "your_supabase_anon_key",
    "your_supabase_url",
    "your_key",
    "placeholder",
    "changeme",
    "none",
}


def _get_secret(name: str) -> Optional[str]:
    """Retrieve secret from environment or Streamlit secrets, ignoring placeholders."""
    value = os.getenv(name)
    if not value:
        try:
            import streamlit as st

            value = st.secrets.get(name)
        except Exception:
            value = None

    if value and str(value).strip().lower() in PLACEHOLDER_SECRETS:
        return None
    return value.strip() if value else None


def is_configured() -> bool:
    """Return True only if valid non-placeholder Supabase credentials exist."""
    return bool(_get_secret("SUPABASE_URL") and _get_secret("SUPABASE_KEY"))


def get_client():
    """Create (once) and return the Supabase client, or None if unavailable."""
    global _client
    if _client is not None:
        return _client

    url, key = _get_secret("SUPABASE_URL"), _get_secret("SUPABASE_KEY")
    if not url or not key:
        return None

    try:
        from supabase import create_client

        _client = create_client(url, key)
    except Exception as exc:
        logger.warning("Could not initialize Supabase client: %s", exc)
        _client = None
    return _client


def save_scan(
    input_type: str,
    content: str,
    verdict: str,
    confidence: Optional[float] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """
    Insert one scan log into Supabase (if configured) or local session memory.
    Sensitive tokens in content are automatically masked.
    Returns (success, message).
    """
    if input_type not in VALID_TYPES:
        return False, f"Invalid input_type '{input_type}'."

    # Redact sensitive data before storage
    safe_content = mask_sensitive_text(content, max_length=500)
    created_at = datetime.now(timezone.utc).isoformat()

    row = {
        "input_type": input_type,
        "content": safe_content,
        "verdict": verdict,
        "confidence": round(float(confidence), 3) if confidence is not None else None,
        "details": details or {},
        "created_at": created_at,
    }

    # Always save to local session buffer so history works offline
    _local_history.insert(0, row)
    if len(_local_history) > 200:
        _local_history.pop()

    if not is_configured():
        return True, "Saved to local session log (Supabase not configured)."

    client = get_client()
    if client is None:
        return True, "Saved to local session log (Supabase unreachable)."

    try:
        client.table(TABLE).insert(row).execute()
        return True, "Saved to cloud scan history."
    except Exception as exc:
        logger.warning("Failed to save scan to Supabase: %s", exc)
        return True, f"Saved to local log (Cloud sync issue: {exc})"


def fetch_history(
    limit: int = 100, input_type: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Return (rows, status_or_error_message). Newest first.
    If Supabase is configured and reachable, fetches from database.
    Otherwise returns local in-memory session history.
    """
    if not is_configured():
        filtered = [
            r for r in _local_history
            if not input_type or r.get("input_type") == input_type
        ][:limit]
        note = "Showing local session logs. (Supabase is not configured - set SUPABASE_URL and SUPABASE_KEY to persist across restarts)."
        return filtered, note

    client = get_client()
    if client is None:
        filtered = [
            r for r in _local_history
            if not input_type or r.get("input_type") == input_type
        ][:limit]
        return filtered, "Supabase client could not be created; showing local session logs."

    try:
        query = client.table(TABLE).select("*").order("created_at", desc=True).limit(limit)
        if input_type:
            query = query.eq("input_type", input_type)
        response = query.execute()
        cloud_rows = response.data or []
        return cloud_rows, None
    except Exception as exc:
        logger.warning("Failed to fetch history from Supabase: %s", exc)
        filtered = [
            r for r in _local_history
            if not input_type or r.get("input_type") == input_type
        ][:limit]
        return filtered, f"Could not load from Supabase ({exc}); showing local session logs."


def clear_local_history() -> None:
    """Clear in-memory session logs (primarily for testing)."""
    global _local_history
    _local_history.clear()
