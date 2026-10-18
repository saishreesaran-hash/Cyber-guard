"""Tests for url_scanner module."""

from unittest.mock import MagicMock, patch
import pytest
from modules.url_scanner import (
    URLScannerError,
    analyze_url,
    get_api_key,
    is_virustotal_configured,
    local_heuristics,
    normalize_url,
    scan_url_virustotal,
)


def test_normalize_url_valid():
    assert normalize_url("google.com") == "http://google.com"
    assert normalize_url("https://example.com/test?a=1") == "https://example.com/test?a=1"
    assert normalize_url("http://192.168.1.1/admin") == "http://192.168.1.1/admin"


def test_normalize_url_invalid_scheme():
    with pytest.raises(URLScannerError, match="Invalid URL protocol"):
        normalize_url("javascript:alert(1)")

    with pytest.raises(URLScannerError, match="Invalid URL protocol"):
        normalize_url("file:///etc/passwd")

    with pytest.raises(URLScannerError, match="Invalid URL protocol"):
        normalize_url("data:text/html,<script>alert(1)</script>")


def test_normalize_url_empty():
    with pytest.raises(URLScannerError, match="enter a URL"):
        normalize_url("")

    with pytest.raises(URLScannerError, match="enter a URL"):
        normalize_url("   ")


def test_local_heuristics_benign():
    heur = local_heuristics("https://www.google.com")
    assert heur["verdict"] in ("Clean", "Warning")
    assert heur["suspicious"] is False


def test_local_heuristics_suspicious_ip():
    heur = local_heuristics("http://192.168.1.1/login.php")
    assert heur["suspicious"] is True
    assert any("IP address" in n for n in heur["notes"])


def test_local_heuristics_suspicious_tld_and_keywords():
    heur = local_heuristics("http://secure-update-kyc.sbi-alert.xyz/verify")
    assert heur["suspicious"] is True
    assert any("top-level domain" in n.lower() for n in heur["notes"])


def test_placeholder_api_key_detection(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "your_virustotal_api_key")
    assert get_api_key() is None
    assert is_virustotal_configured() is False


def test_analyze_url_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    res = analyze_url("https://example.com")
    assert res["is_vt_available"] is False
    assert res["virustotal"] is None
    assert "not configured" in res["vt_error"].lower()
    assert res["verdict"] in ("Clean", "Warning", "Suspicious")


@patch("modules.url_scanner.requests.get")
def test_scan_url_virustotal_mock_success(mock_get, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "valid_test_api_key_12345")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 10,
                },
                "last_analysis_results": {
                    "VendorA": {"category": "malicious", "result": "phishing"},
                    "VendorB": {"category": "malicious", "result": "malware"},
                },
                "reputation": -20,
            }
        }
    }
    mock_get.return_value = mock_resp

    report = scan_url_virustotal("https://malicious-example.com")
    assert report["verdict"] == "Malicious"
    assert report["malicious"] == 5
    assert len(report["flagged_vendors"]) == 2


@patch("modules.url_scanner.requests.get")
def test_scan_url_virustotal_rate_limit(mock_get, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "valid_test_api_key_12345")
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.return_value = mock_resp

    with pytest.raises(URLScannerError, match="rate limit exceeded"):
        scan_url_virustotal("https://example.com")
