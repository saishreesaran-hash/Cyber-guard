"""
URL Threat Scanner using VirusTotal API v3 and Local Security Heuristics.

Security & Reliability features:
1. Strict URL validation: Only http and https protocols permitted; rejects javascript:, data:, file:, etc.
2. Sanitization: Strips credentials and redacts sensitive query parameters before external requests/logging.
3. API Key Management: Detects placeholder keys (e.g. your_virustotal_api_key) and handles missing keys without crashing.
4. Offline Heuristics: Performs comprehensive local structure checks (IP hosts, Punycode, suspicious TLDs, phishing keywords)
   even when VirusTotal is unavailable.
5. Distinction of Results: Clearly distinguishes local heuristic warnings from external vendor threat intelligence.
"""

from __future__ import annotations

import base64
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from modules.security_utils import sanitize_url_for_logging

VT_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15
MAX_URL_LENGTH = 2048

# Placeholder keys to ignore
PLACEHOLDER_KEYS = {
    "your_virustotal_api_key",
    "your_api_key",
    "placeholder",
    "changeme",
    "none",
    "api_key_here",
}

ALLOWED_SCHEMES = {"http", "https"}


class URLScannerError(Exception):
    """Raised for user-facing scanner issues (bad URL, missing key, API errors)."""


def get_api_key() -> Optional[str]:
    """Retrieve VirusTotal API key from environment or Streamlit secrets, ignoring placeholders."""
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        try:
            import streamlit as st

            key = st.secrets.get("VIRUSTOTAL_API_KEY")
        except Exception:
            key = None

    if key and str(key).strip().lower() in PLACEHOLDER_KEYS:
        return None
    return key.strip() if key else None


def is_virustotal_configured() -> bool:
    """Check if a valid, non-placeholder VirusTotal API key is present."""
    return bool(get_api_key())


def normalize_url(url: Optional[str]) -> str:
    """Validate, clean, and normalize a user-supplied URL."""
    if not url or not isinstance(url, str):
        raise URLScannerError("Please enter a URL to analyze.")

    raw = url.strip()
    if not raw:
        raise URLScannerError("Please enter a URL to analyze.")

    if len(raw) > MAX_URL_LENGTH:
        raise URLScannerError(f"URL is too long (exceeds {MAX_URL_LENGTH} characters).")

    # Check if a scheme is already present (e.g. "https://", "ftp://", "javascript:")
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", raw)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme not in ALLOWED_SCHEMES:
            raise URLScannerError(
                f"Invalid URL protocol '{scheme}'. Only http:// and https:// URLs are supported."
            )
    else:
        raw = "http://" + raw

    try:
        parsed = urlparse(raw)
    except Exception as exc:
        raise URLScannerError(f"Malformed URL: {exc}")

    if not parsed.netloc:
        raise URLScannerError("The URL does not contain a valid domain or host name.")

    # Remove default ports
    host = parsed.hostname
    if not host or "." not in host and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        if host != "localhost":
            raise URLScannerError("That does not look like a valid domain or IP address.")

    return raw


def _url_id(url: str) -> str:
    """Generate VirusTotal base64url identifier without '=' padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _headers(api_key: str) -> Dict[str, str]:
    return {"x-apikey": api_key, "accept": "application/json"}


def _parse_report(attributes: Dict[str, Any], url: str) -> Dict[str, Any]:
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected

    if malicious >= 3:
        verdict = "Malicious"
    elif malicious >= 1 or suspicious >= 2:
        verdict = "Suspicious"
    elif total == 0:
        verdict = "Unknown"
    else:
        verdict = "Clean"

    results = attributes.get("last_analysis_results") or attributes.get("results") or {}
    flagged = [
        {"vendor": vendor, "category": r.get("category"), "result": r.get("result")}
        for vendor, r in results.items()
        if r.get("category") in ("malicious", "suspicious")
    ]

    return {
        "url": sanitize_url_for_logging(url),
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "flagged_vendors": flagged,
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories", {}),
        "source": "VirusTotal API v3",
    }


def scan_url_virustotal(url: str, api_key: Optional[str] = None, wait_seconds: int = 15) -> Dict[str, Any]:
    """
    Query the VirusTotal API v3 for a given URL.
    Raises URLScannerError with user-friendly error messages on API failure or rate limit.
    """
    api_key = api_key or get_api_key()
    if not api_key:
        raise URLScannerError(
            "VirusTotal API key is not configured. Set VIRUSTOTAL_API_KEY in your environment or .env file."
        )

    norm_url = normalize_url(url)
    headers = _headers(api_key)

    try:
        # 1. Check if report already exists (fast path)
        resp = requests.get(
            f"{VT_BASE}/urls/{_url_id(norm_url)}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 200:
            data = resp.json()
            return _parse_report(data["data"]["attributes"], norm_url)

        if resp.status_code == 401:
            raise URLScannerError("VirusTotal authentication failed (401). Please check that your API key is valid.")
        if resp.status_code == 429:
            raise URLScannerError("VirusTotal rate limit exceeded (free tier allows 4 requests/min). Please try again shortly.")
        if resp.status_code != 404:
            raise URLScannerError(f"VirusTotal responded with HTTP status {resp.status_code}.")

        # 2. Not seen before: submit for scanning and poll
        submit = requests.post(
            f"{VT_BASE}/urls",
            headers=headers,
            data={"url": norm_url},
            timeout=REQUEST_TIMEOUT,
        )
        if submit.status_code == 429:
            raise URLScannerError("VirusTotal rate limit reached. Please try again shortly.")
        if submit.status_code not in (200, 201):
            raise URLScannerError(f"Could not submit URL to VirusTotal (HTTP {submit.status_code}).")

        analysis_id = submit.json()["data"]["id"]
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            time.sleep(3)
            poll = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            if poll.status_code == 200:
                attrs = poll.json()["data"]["attributes"]
                if attrs.get("status") == "completed":
                    return _parse_report(attrs, norm_url)

        raise URLScannerError("VirusTotal analysis is still in progress. Please check again in a moment.")

    except requests.exceptions.Timeout:
        raise URLScannerError("VirusTotal request timed out. Please try again.")
    except requests.exceptions.ConnectionError:
        raise URLScannerError("Could not connect to VirusTotal. Check your internet connection or proxy settings.")
    except requests.exceptions.RequestException as exc:
        raise URLScannerError(f"Network error contacting VirusTotal: {exc}")
    except (KeyError, ValueError) as exc:
        raise URLScannerError(f"Unexpected response format from VirusTotal: {exc}")


def local_heuristics(url: str) -> Dict[str, Any]:
    """
    Offline structural checks on URL patterns, suspicious TLDs, IP formats, and lookalike domains.
    Always safe to run without external dependencies or internet.
    """
    norm_url = normalize_url(url)
    parsed = urlparse(norm_url)
    host = (parsed.hostname or "").lower()
    notes: List[str] = []

    if parsed.scheme == "http":
        notes.append("Unencrypted connection (HTTP instead of HTTPS)")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        notes.append("Host is a direct IP address rather than a domain name")
    if host.count(".") >= 4:
        notes.append("Unusually high number of subdomains")
    if "@" in parsed.netloc:
        notes.append("Contains '@' symbol (can conceal actual destination)")
    if host.startswith("xn--") or ".xn--" in host:
        notes.append("Internationalized/Punycode domain (potential visual spoofing/IDN homograph)")
    if re.search(r"\.(xyz|top|tk|ml|ga|cf|gq|click|buzz|work|info|rest|icu)$", host):
        notes.append("Top-level domain (TLD) has a high statistical correlation with malicious campaigns")
    if re.search(r"(login|verify|secure|update|kyc|account|wallet|banking|support|password)", norm_url.lower()) and host.count("-") >= 1:
        notes.append("Contains sensitive security keywords combined with hyphenated domain name")
    if len(norm_url) > 120:
        notes.append("Extremely long URL (often used to obscure target domain)")

    is_suspicious = len(notes) >= 2 or any("IP address" in n or "Conceal" in n for n in notes)

    return {
        "url": norm_url,
        "notes": notes,
        "suspicious": is_suspicious,
        "verdict": "Suspicious" if is_suspicious else ("Warning" if notes else "Clean"),
        "assessment_type": "Offline Structural Heuristics (Not Vendor Confirmed)",
    }


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Unified URL analysis combining local heuristics and VirusTotal intelligence.
    Fails soft if VirusTotal is not configured or unavailable.
    """
    norm = normalize_url(url)
    heuristics = local_heuristics(norm)
    vt_report: Optional[Dict[str, Any]] = None
    vt_error: Optional[str] = None

    if is_virustotal_configured():
        try:
            vt_report = scan_url_virustotal(norm)
        except URLScannerError as exc:
            vt_error = str(exc)
        except Exception as exc:
            vt_error = f"VirusTotal query failed: {exc}"
    else:
        vt_error = "VirusTotal API key not configured (offline heuristics only)."

    # Determine overall verdict
    if vt_report:
        verdict = vt_report["verdict"]
        # If VT says clean but offline heuristics found multiple severe red flags, warn user
        if verdict == "Clean" and heuristics["suspicious"]:
            verdict = "Suspicious"
    else:
        verdict = heuristics["verdict"]

    return {
        "normalized_url": norm,
        "verdict": verdict,
        "heuristics": heuristics,
        "virustotal": vt_report,
        "vt_error": vt_error,
        "is_vt_available": is_virustotal_configured(),
        "assessment_type": "Multi-Layer URL Threat Analysis",
    }


# Backwards compatibility alias
scan_url = scan_url_virustotal
