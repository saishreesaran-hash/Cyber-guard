"""Tests for security_utils module."""

import pytest
from modules.security_utils import (
    mask_sensitive_text,
    sanitize_url_for_logging,
    validate_image_bytes,
)


def test_mask_sensitive_text_otp():
    text = "Your login OTP: 582914 is confidential. Never share your otp with anyone."
    masked = mask_sensitive_text(text)
    assert "582914" not in masked
    assert "[REDACTED_CODE]" in masked


def test_mask_sensitive_text_credit_card():
    text = "Payment processed on card 4111 2222 3333 4444 successfully."
    masked = mask_sensitive_text(text)
    assert "4111 2222 3333 4444" not in masked
    assert "[CARD_REDACTED_...4444]" in masked


def test_mask_sensitive_text_password():
    text = "Please set your password: SecretPassword123! to proceed."
    masked = mask_sensitive_text(text)
    assert "SecretPassword123!" not in masked
    assert "[REDACTED_PASSWORD]" in masked


def test_mask_sensitive_text_empty():
    assert mask_sensitive_text("") == ""
    assert mask_sensitive_text(None) == ""


def test_mask_sensitive_text_truncation():
    long_text = "A" * 1500
    masked = mask_sensitive_text(long_text, max_length=100)
    assert len(masked) < 200
    assert "[TRUNCATED]" in masked


def test_sanitize_url_embedded_credentials():
    url = "https://admin:supersecret@example.com/dashboard"
    sanitized = sanitize_url_for_logging(url)
    assert "supersecret" not in sanitized
    assert "admin" not in sanitized
    assert "example.com" in sanitized


def test_sanitize_url_sensitive_params():
    url = "https://example.com/verify?token=abc123xyz&otp=9999&redirect=/home&auth_token=secret789"
    sanitized = sanitize_url_for_logging(url)
    assert "abc123xyz" not in sanitized
    assert "9999" not in sanitized
    assert "secret789" not in sanitized
    assert "token=%5BREDACTED%5D" in sanitized or "token=[REDACTED]" in sanitized
    assert "redirect=%2Fhome" in sanitized or "redirect=/home" in sanitized


def test_validate_image_bytes_valid():
    # PNG header
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    valid, msg = validate_image_bytes(png_bytes)
    assert valid is True
    assert msg == "Valid"

    # JPEG header
    jpeg_bytes = b"\xff\xd8\xff" + b"\x00" * 50
    valid, msg = validate_image_bytes(jpeg_bytes)
    assert valid is True


def test_validate_image_bytes_empty():
    valid, msg = validate_image_bytes(b"")
    assert valid is False
    assert "empty" in msg.lower()


def test_validate_image_bytes_invalid_format():
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00"
    valid, msg = validate_image_bytes(fake_exe)
    assert valid is False
    assert "unsupported" in msg.lower()


def test_validate_image_bytes_oversized():
    huge_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200
    valid, msg = validate_image_bytes(huge_data, max_bytes=100)
    assert valid is False
    assert "exceeds" in msg.lower()
