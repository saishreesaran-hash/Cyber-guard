"""Tests for supabase_client module."""

import pytest
from database.supabase_client import (
    clear_local_history,
    fetch_history,
    is_configured,
    save_scan,
)


@pytest.fixture(autouse=True)
def clean_history():
    clear_local_history()
    yield
    clear_local_history()


def test_is_configured_without_keys(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    assert is_configured() is False


def test_is_configured_with_placeholders(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://your-project.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "your_supabase_anon_key")
    assert is_configured() is False


def test_save_scan_local_fallback():
    ok, msg = save_scan(
        input_type="text",
        content="Urgent alert with OTP 948271 on card 4111 2222 3333 4444",
        verdict="High Risk",
        confidence=0.88,
        details={"risk_score": 0.88},
    )
    assert ok is True
    assert "session log" in msg.lower() or "saved" in msg.lower()

    # Verify retrieval
    rows, note = fetch_history(limit=10)
    assert len(rows) == 1
    stored = rows[0]
    assert stored["input_type"] == "text"
    assert stored["verdict"] == "High Risk"
    # Ensure sensitive content was redacted prior to storage
    assert "948271" not in stored["content"]
    assert "4111 2222 3333 4444" not in stored["content"]
    assert "[REDACTED_CODE]" in stored["content"]
    assert "[CARD_REDACTED_" in stored["content"]


def test_save_scan_invalid_input_type():
    ok, msg = save_scan(
        input_type="invalid_type",
        content="test content",
        verdict="Safe",
    )
    assert ok is False
    assert "invalid input_type" in msg.lower()


def test_fetch_history_filtering():
    save_scan("text", "Message 1", "Safe")
    save_scan("url", "https://example.com", "Clean")
    save_scan("text", "Message 2", "Warning")

    text_rows, _ = fetch_history(limit=10, input_type="text")
    assert len(text_rows) == 2
    assert all(r["input_type"] == "text" for r in text_rows)

    url_rows, _ = fetch_history(limit=10, input_type="url")
    assert len(url_rows) == 1
    assert url_rows[0]["input_type"] == "url"
