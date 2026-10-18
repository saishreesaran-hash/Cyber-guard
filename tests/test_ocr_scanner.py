"""Tests for ocr_scanner module."""

import io
import numpy as np
from PIL import Image, ImageDraw
import pytest

from modules.ocr_scanner import (
    OCRScannerError,
    error_level_analysis,
    glyph_height_check,
    is_tesseract_available,
    load_image,
    parse_fields,
    preprocess,
    scan_payment_image,
    validate_transaction,
)


def _create_test_image_bytes(text: str = "₹ 1,500.00 Paid Successfully") -> bytes:
    """Helper to generate a clean synthetic payment receipt image."""
    img = Image.new("RGB", (400, 300), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.rectangle([(20, 20), (380, 280)], outline=(200, 200, 200), width=2)
    draw.text((40, 50), text, fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_load_image_valid():
    data = _create_test_image_bytes()
    img = load_image(data)
    assert isinstance(img, np.ndarray)
    assert img.shape[0] == 300
    assert img.shape[1] == 400


def test_load_image_empty():
    with pytest.raises(OCRScannerError, match="empty"):
        load_image(b"")


def test_load_image_corrupted():
    with pytest.raises(OCRScannerError, match="Unsupported or invalid"):
        load_image(b"not an image at all but random text bytes")


def test_preprocess():
    data = _create_test_image_bytes()
    img = load_image(data)
    thresh = preprocess(img)
    assert isinstance(thresh, np.ndarray)
    assert len(thresh.shape) == 2  # Grayscale binary


def test_error_level_analysis():
    data = _create_test_image_bytes()
    img = load_image(data)
    ela = error_level_analysis(img)
    assert "mean" in ela
    assert "std" in ela
    assert "suspicious" in ela
    assert isinstance(ela["suspicious"], (bool, np.bool_))


def test_parse_fields():
    receipt_text = """
    Paid to Ramesh Sharma
    UPI ID: ramesh@okhdfcbank
    ₹ 1,250.00
    Transaction ID: 294817492817
    Date: 14 Oct 2026 12:45 PM
    Status: Completed
    """
    fields = parse_fields(receipt_text)
    assert fields["amount"] == "1250.00"
    assert fields["upi_id"] == "ramesh@okhdfcbank"
    assert fields["transaction_id"] == "294817492817"
    assert fields["status"] == "Completed"


def test_scan_payment_image_graceful_execution():
    """Ensure scan_payment_image returns a valid analysis result even if Tesseract is not installed."""
    data = _create_test_image_bytes()
    res = scan_payment_image(data)
    assert "validation" in res
    assert "verdict" in res["validation"]
    assert "risk_points" in res["validation"]
    assert "ela" in res["validation"]
    assert "disclaimer" in res["validation"]
    assert "fields" in res
    if not is_tesseract_available():
        assert res["ocr_available"] is False
    else:
        assert res["ocr_available"] is True


def test_validate_transaction_heuristics():
    data = _create_test_image_bytes()
    img = load_image(data)
    # Test with unrecognized UPI handle and unusual transaction ID
    suspicious_fields = {
        "amount": "5000",
        "upi_id": "scammer@unknownfakebank",
        "transaction_id": "INVALID",
        "status": "Failed",
    }
    val = validate_transaction(suspicious_fields, [], img, data, ocr_ran=True)
    assert val["risk_points"] >= 2
    assert val["verdict"] in ("Warning", "High Risk")
    assert any("UPI banking handle" in rf for rf in val["red_flags"])
