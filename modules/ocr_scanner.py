"""
OCR Payment Screenshot Scanner & Forensics Engine.

Pipeline:
1. File Validation: Checks magic bytes, size limits, and image dimensions to protect against malformed files and decompression bombs.
2. Image Preprocessing: Grayscale -> upscale (small images) -> denoise -> adaptive thresholding.
3. OCR Text Extraction (via pytesseract, when Tesseract OCR is installed).
4. Heuristic Forgery & Integrity Analysis:
   - Error Level Analysis (ELA): detects localized JPEG re-compression differences
   - Image metadata inspection: scans for image editor footprints (Photoshop, Canva, GIMP, PicsArt, etc.)
   - Glyph height consistency and OCR confidence scoring
   - UPI transaction field parsing and sanity checks (UPI handles, UTR/transaction ID format, status)
5. Graceful Fallback: When the Tesseract OCR binary is not installed on the system, the scanner
   automatically performs image tampering forensics (ELA + metadata) and clearly informs the user
   without crashing.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import statistics
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np
from PIL import Image

from modules.security_utils import validate_image_bytes

# Tesseract setup & detection
try:
    import pytesseract
    from pytesseract import Output
except ImportError:
    pytesseract = None
    Output = None

# Common Tesseract paths on Windows
COMMON_WINDOWS_TESSERACT_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Tesseract-OCR\tesseract.exe"),
    os.path.expandvars(r"%PROGRAMFILES%\Tesseract-OCR\tesseract.exe"),
]

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_DIMENSION = 8000  # Protection against decompression bombs

KNOWN_UPI_HANDLES = {
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "paytm", "apl", "upi",
    "sbi", "hdfcbank", "icici", "axisbank", "kotak", "pnb", "boi", "barodampay", "fbl",
    "yesbank", "indus", "idfcbank", "airtel", "jio", "postbank", "cnrb", "unionbank",
}
EDIT_SOFTWARE = [
    "photoshop", "gimp", "canva", "picsart", "snapseed", "pixlr",
    "paint.net", "lightroom", "editor", "photodirector", "fotor",
]


class OCRScannerError(Exception):
    """User-facing OCR scanner error."""


def get_tesseract_path() -> Optional[str]:
    """Find the path to the Tesseract binary if available."""
    # 1. Environment variable
    env_cmd = os.getenv("TESSERACT_CMD")
    if env_cmd and os.path.isfile(env_cmd):
        return env_cmd

    # 2. On system PATH
    which_tess = shutil.which("tesseract")
    if which_tess:
        return which_tess

    # 3. Known Windows locations
    for p in COMMON_WINDOWS_TESSERACT_PATHS:
        if os.path.isfile(p):
            return p

    return None


def is_tesseract_available() -> bool:
    """Return True if pytesseract is installed and a working tesseract binary is found."""
    if pytesseract is None:
        return False
    path = get_tesseract_path()
    if path:
        try:
            pytesseract.pytesseract.tesseract_cmd = path
            return True
        except Exception:
            return False
    return False


# Configure pytesseract path if discovered
_discovered_path = get_tesseract_path()
if pytesseract is not None and _discovered_path:
    pytesseract.pytesseract.tesseract_cmd = _discovered_path


# --------------------------------------------------------------------------- #
# Image loading / preprocessing
# --------------------------------------------------------------------------- #
def load_image(data: bytes) -> np.ndarray:
    """Validate and decode image bytes into an OpenCV BGR numpy array."""
    valid, msg = validate_image_bytes(data, max_bytes=MAX_IMAGE_BYTES)
    if not valid:
        raise OCRScannerError(msg)

    # Validate image dimensions using PIL first to avoid decompression attacks
    try:
        with Image.open(io.BytesIO(data)) as pil_img:
            w, h = pil_img.size
            if w > MAX_IMAGE_DIMENSION or h > MAX_IMAGE_DIMENSION:
                raise OCRScannerError(
                    f"Image dimensions ({w}x{h}) are too large. Max permitted is {MAX_IMAGE_DIMENSION}px."
                )
    except OCRScannerError:
        raise
    except Exception as exc:
        raise OCRScannerError(f"Could not open image file: {exc}")

    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise OCRScannerError("Could not decode image data. Please ensure it is a valid PNG or JPG file.")
    return img


def preprocess(img: np.ndarray) -> np.ndarray:
    """Grayscale -> upscale (small images) -> denoise -> adaptive threshold."""
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape
    if max(h, w) < 1400:
        scale = 1400 / max(h, w)
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
    gray = cv2.fastNlMeansDenoising(gray, None, h=12, templateWindowSize=7, searchWindowSize=21)
    # Dark-mode screenshots: invert so text is dark on light
    if np.mean(gray) < 110:
        gray = cv2.bitwise_not(gray)
    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 10
    )
    return thresh


# --------------------------------------------------------------------------- #
# OCR
# --------------------------------------------------------------------------- #
def run_ocr(processed: np.ndarray) -> Tuple[str, List[Dict[str, Any]]]:
    """Return extracted text and word bounding boxes."""
    if not is_tesseract_available():
        raise OCRScannerError(
            "Tesseract OCR engine is not installed on this system. "
            "To enable text extraction, install Tesseract OCR or deploy via the provided Docker container."
        )

    try:
        data = pytesseract.image_to_data(processed, config="--oem 3 --psm 6", output_type=Output.DICT)
    except Exception as exc:
        raise OCRScannerError(f"Tesseract OCR execution failed: {exc}")

    words, lines = [], {}
    for i, txt in enumerate(data.get("text", [])):
        txt = txt.strip()
        if not txt:
            continue
        try:
            conf = float(data["conf"][i])
        except (ValueError, TypeError):
            conf = -1.0
        if conf < 0:
            continue
        line_id = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        word = {
            "text": txt,
            "conf": conf,
            "left": data["left"][i],
            "top": data["top"][i],
            "width": data["width"][i],
            "height": data["height"][i],
            "line_id": line_id,
        }
        words.append(word)
        lines.setdefault(line_id, []).append(txt)

    text = "\n".join(" ".join(v) for v in lines.values())
    return text, words


# --------------------------------------------------------------------------- #
# Field parsing
# --------------------------------------------------------------------------- #
AMOUNT_RE = re.compile(r"(?:₹|rs\.?|inr)\s*([\d,]+(?:\.\d{1,2})?)", re.I)
UPI_RE = re.compile(r"\b([a-z0-9][a-z0-9._-]{1,}@[a-z][a-z0-9]{1,})\b", re.I)
TXN_ID_RE = re.compile(r"(?:utr|upi ref(?:erence)?(?: no)?|transaction id|txn id|ref(?:erence)? no\.?)\s*[:#-]?\s*([A-Z0-9]{8,24})", re.I)
DATE_RE = re.compile(
    r"(\d{1,2}[\s/\-](?:[A-Za-z]{3,9}|\d{1,2})[\s/\-,]*\d{2,4})|(\d{4}-\d{2}-\d{2})", re.I
)
TIME_RE = re.compile(r"\b(\d{1,2}:\d{2}(?::\d{2})?\s*(?:am|pm)?)\b", re.I)
STATUS_EXPLICIT_RE = re.compile(
    r"(?:payment\s+status|txn\s+status|status)\s*[:\-]?\s*(success(?:ful)?|completed|paid|failed|pending|processing)\b",
    re.I,
)
STATUS_FALLBACK_RE = re.compile(r"\b(success(?:ful)?|completed|failed|pending|processing|paid)\b", re.I)
RECEIVER_RE = re.compile(r"(?:paid to|to|sent to|receiver|beneficiary)\s*[:\-]?\s*([A-Za-z][A-Za-z .]{2,40})", re.I)


def parse_fields(text: str) -> Dict[str, Any]:
    amounts = [a.replace(",", "") for a in AMOUNT_RE.findall(text)]
    upi_ids = UPI_RE.findall(text)
    txn = TXN_ID_RE.search(text)
    date = DATE_RE.search(text)
    time_ = TIME_RE.search(text)
    status = STATUS_EXPLICIT_RE.search(text) or STATUS_FALLBACK_RE.search(text)
    receiver = RECEIVER_RE.search(text)
    return {
        "amount": amounts[0] if amounts else None,
        "all_amounts": amounts,
        "upi_id": upi_ids[0] if upi_ids else None,
        "all_upi_ids": upi_ids,
        "receiver_name": receiver.group(1).strip() if receiver else None,
        "transaction_id": txn.group(1) if txn else None,
        "date": date.group(0).strip() if date else None,
        "time": time_.group(1) if time_ else None,
        "status": status.group(1).capitalize() if status else None,
    }


# --------------------------------------------------------------------------- #
# Forgery heuristics
# --------------------------------------------------------------------------- #
def error_level_analysis(img: np.ndarray, quality: int = 90) -> Dict[str, Any]:
    """
    Error Level Analysis (ELA): Recompress as JPEG. Edited regions often exhibit
    divergent compression error levels relative to the background.
    """
    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    pil = Image.fromarray(rgb)
    buf = io.BytesIO()
    pil.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    recompressed = np.array(Image.open(buf).convert("RGB")).astype(np.int16)
    diff = np.abs(rgb.astype(np.int16) - recompressed).sum(axis=2).astype(np.float32)

    h, w = diff.shape
    gh, gw = 8, 8
    blocks = [
        diff[r * h // gh:(r + 1) * h // gh, c * w // gw:(c + 1) * w // gw].mean()
        for r in range(gh) for c in range(gw)
    ]
    mean, std = float(np.mean(blocks)), float(np.std(blocks))
    max_block = float(np.max(blocks))
    ratio = max_block / (mean + 1e-6)
    return {"mean": mean, "std": std, "max_ratio": ratio, "suspicious": ratio > 3.5 and mean > 1.0}


def check_metadata(data: bytes) -> List[str]:
    """Inspect image EXIF/header metadata for mentions of image manipulation tools."""
    notes = []
    try:
        pil = Image.open(io.BytesIO(data))
        info_str = " ".join(str(v) for v in pil.info.values()).lower()
        try:
            exif = pil.getexif()
            if exif:
                info_str += " " + " ".join(str(v) for v in exif.values()).lower()
        except Exception:
            pass
        for name in EDIT_SOFTWARE:
            if name in info_str:
                notes.append(f"Image metadata reveals manipulation software signature ({name})")
                break
    except Exception:
        pass
    return notes


def glyph_height_check(words: List[Dict[str, Any]], amount: Optional[str]) -> Optional[str]:
    """Check whether digits in the amount line have inconsistent heights."""
    if not amount or len(words) < 6:
        return None
    amount_digits = amount.split(".")[0]
    target = [
        w for w in words
        if amount_digits in re.sub(r"[^\d]", "", w.get("text", ""))
        and len(re.sub(r"\D", "", w.get("text", ""))) >= len(amount_digits)
    ]
    if not target:
        return None
    heights = [w["height"] for w in words if w.get("height", 0) > 4]
    if not heights:
        return None
    median_h = statistics.median(heights)
    amt_h = target[0]["height"]
    same_line = [w for w in words if w.get("line_id") == target[0].get("line_id")]
    if len(same_line) >= 2:
        hs = [w["height"] for w in same_line]
        if max(hs) / max(1, min(hs)) > 2.2 and target[0]["height"] != max(hs):
            return "Text heights on amount line are inconsistent (possible pasted/tampered digits)"
    if amt_h < median_h * 0.5:
        return "Amount digits are unusually small compared to other screenshot text"
    return None


def low_conf_amount(words: List[Dict[str, Any]], amount: Optional[str]) -> Optional[str]:
    """Check for low OCR confidence specifically on the detected amount."""
    if not amount:
        return None
    digits = amount.split(".")[0]
    for w in words:
        if digits in re.sub(r"[^\d]", "", w.get("text", "")) and w.get("conf", 100) < 55:
            return f"Low OCR recognition confidence ({w['conf']:.0f}%) on amount digits, suggesting artifacting or editing"
    return None


def validate_transaction(
    fields: Dict[str, Any],
    words: List[Dict[str, Any]],
    img: np.ndarray,
    raw_bytes: bytes,
    ocr_ran: bool = True,
) -> Dict[str, Any]:
    """
    Evaluate screenshot integrity across field sanity checks and image forensics.
    """
    red_flags: List[str] = []
    notes: List[str] = []
    score = 0

    # Image forensics always run regardless of OCR
    ela = error_level_analysis(img)
    if ela["suspicious"]:
        red_flags.append("Error Level Analysis (ELA) detected compression disparity (possible localized modification)")
        score += 3

    for meta_note in check_metadata(raw_bytes):
        red_flags.append(meta_note)
        score += 3

    if ocr_ran:
        # Field verification
        missing = [k for k in ("amount", "upi_id", "date", "transaction_id") if not fields.get(k)]
        if missing:
            notes.append("Could not locate expected field(s): " + ", ".join(missing))
            score += min(len(missing), 3)

        upi = fields.get("upi_id")
        if upi:
            handle = upi.split("@")[-1].lower()
            if handle not in KNOWN_UPI_HANDLES:
                red_flags.append(f"Unrecognised or unverified UPI banking handle '@{handle}'")
                score += 2

        txn = fields.get("transaction_id")
        if txn and not re.fullmatch(r"\d{12}", txn) and not re.fullmatch(r"[A-Z0-9]{10,24}", txn):
            red_flags.append("Transaction / UTR ID exhibits an irregular format")
            score += 1

        amts = {a.split(".")[0] for a in fields.get("all_amounts", [])}
        if len(amts) > 2:
            red_flags.append("Multiple conflicting amounts identified on the receipt")
            score += 1

        if fields.get("status") and fields["status"].lower() in ("pending", "processing", "failed"):
            red_flags.append(f"Receipt indicates status '{fields['status']}', not a completed payment")
            score += 2

        gh = glyph_height_check(words, fields.get("amount"))
        if gh:
            red_flags.append(gh)
            score += 2

        lc = low_conf_amount(words, fields.get("amount"))
        if lc:
            red_flags.append(lc)
            score += 2
    else:
        notes.append("Text OCR skipped (Tesseract engine not found). Analysis performed using visual forensics only.")

    if score >= 5:
        verdict = "High Risk"
    elif score >= 2:
        verdict = "Warning"
    else:
        verdict = "Safe"

    confidence = round(min(0.95, 0.55 + 0.07 * score), 2) if verdict != "Safe" else round(max(0.5, 0.9 - 0.15 * score), 2)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_points": score,
        "red_flags": red_flags,
        "notes": notes,
        "ela": {k: (round(v, 3) if isinstance(v, float) else v) for k, v in ela.items()},
        "assessment_type": "Heuristic Screenshot Integrity Analysis (Not Bank-Confirmed Fraud)",
        "disclaimer": "Receipt integrity analysis uses pattern heuristics and image forensics. Always verify payments directly in your official banking or UPI app.",
    }


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def scan_payment_image(data: bytes) -> Dict[str, Any]:
    """
    Analyze a payment screenshot. Raises OCRScannerError for malformed files.
    Gracefully falls back to visual forensics if Tesseract OCR is not installed.
    """
    img = load_image(data)

    if not is_tesseract_available():
        # Fallback mode: image forensics only
        validation = validate_transaction(
            fields={},
            words=[],
            img=img,
            raw_bytes=data,
            ocr_ran=False,
        )
        return {
            "fields": {
                "amount": None,
                "upi_id": None,
                "receiver_name": None,
                "transaction_id": None,
                "date": None,
                "time": None,
                "status": None,
            },
            "validation": validation,
            "extracted_text": "[OCR Engine Unavailable - Visual Forensics Only]",
            "ocr_available": False,
        }

    # Full OCR + forensics mode
    processed = preprocess(img)
    text, words = run_ocr(processed)
    fields = parse_fields(text)
    validation = validate_transaction(fields, words, img, data, ocr_ran=True)

    return {
        "fields": fields,
        "validation": validation,
        "extracted_text": text,
        "ocr_available": True,
    }
