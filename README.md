# 🛡️ Digital Fraud & Threat Defense Guard

An AI-driven cybersecurity defense application built with Python and Streamlit. The system detects social engineering, financial fraud, phishing links, tampered UPI receipts, and rogue spyware apps using machine learning, computer vision, and heuristic rule engines.

---

## 📑 Table of Contents
1. [Overview & Architecture](#overview--architecture)
2. [Core Modules & Dashboard Tabs](#core-modules--dashboard-tabs)
3. [Security & Privacy Features](#security--privacy-features)
4. [Project Structure](#project-structure)
5. [Local Quickstart](#local-quickstart)
6. [Environment Configuration](#environment-configuration)
7. [Tesseract OCR Setup](#tesseract-ocr-setup)
8. [Automated Testing](#automated-testing)
9. [Docker Deployment](#docker-deployment)
10. [Cloud Deployment Guides](#cloud-deployment-guides)
11. [Known Limitations & Disclaimers](#known-limitations--disclaimers)

---

## 🔍 Overview & Architecture

```
                    +--------------------------------------------------+
                    |          Streamlit Web Dashboard (app.py)        |
                    +-------------------------+------------------------+
                                              |
     +--------------------+-------------------+-------------------+--------------------+
     |                    |                                       |                    |
     v                    v                                       v                    v
+----+-------------+ +----+------------------+             +-----+--------------+ +----+---------------+
| Message & SMS    | | UPI Payment           |             | URL & Phishing     | | App Permission    |
| Analyzer         | | Screenshot Forensics  |             | Link Scanner       | | Health Auditor    |
| (nlp_analyzer.py)| | (ocr_scanner.py)      |             | (url_scanner.py)   | |(anomaly_detector) |
+----+-------------+ +----+------------------+             +-----+--------------+ +----+--------------+
     |                    |                                       |                    |
     | TF-IDF +           | ELA, Metadata,                        | VirusTotal v3      | Isolation Forest   |
     | Logistic Regr.     | Glyph Height Check                    | & Local Heuristics | Anomaly Outlier    |
     | + Pattern Rules    | + Tesseract OCR                       | (IDN/Punycode/TLD) | Scoring            |
     +---------+----------+---------+-----------------------------+----------+---------+----------+-------+
               |                    |                                        |                    |
               +--------------------+-------------------+--------------------+--------------------+
                                                        |
                                                        v
                                          +-------------+-------------+
                                          |   Data Sanitizer & Masker |
                                          |    (security_utils.py)    |
                                          | (Redacts OTPs/Cards/PWs)  |
                                          +-------------+-------------+
                                                        |
                                                        v
                                          +-------------+-------------+
                                          | Database Client           |
                                          | (supabase_client.py)      |
                                          | Cloud Supabase / Local    |
                                          | In-Memory Session Storage |
                                          +---------------------------+
```

---

## 🚀 Core Modules & Dashboard Tabs

### Tab 1: Message & Payment Analyzer
- **Message Scam Detection (`modules/nlp_analyzer.py`)**:
  - Blends a trained TF-IDF + Logistic Regression machine learning model with specialized regular expression rule engines.
  - Detects urgency threats, OTP/credential harvesting, advance-fee fraud, fake lottery wins, and remote desktop scams (AnyDesk/TeamViewer).
  - Highlights flagged keywords in bold and provides an interactive risk percentage bar.
- **Payment Receipt Integrity (`modules/ocr_scanner.py`)**:
  - Preprocesses payment screenshots using OpenCV (grayscale, adaptive Gaussian thresholding, cubic upscaling).
  - Evaluates digital tampering via **Error Level Analysis (ELA)** to spot recompressed edited regions.
  - Scans image EXIF/header metadata for image-editing signatures (Photoshop, Canva, GIMP, PicsArt).
  - Parses UPI IDs, transaction/UTR numbers, dates, and amounts via OCR.
  - **Fail-soft Architecture**: If Tesseract OCR is not installed on the host machine, the system automatically runs visual tampering forensics (ELA + metadata) without crashing.

### Tab 2: URL & Phishing Link Checker (`modules/url_scanner.py`)
- **Multi-Vendor Cloud Intelligence**: Integrates with VirusTotal API v3 to query 70+ antivirus engines and security databases.
- **Offline Structural Heuristics**: Validates URL structure even without internet or API keys:
  - Detects raw IP address hosts, unencrypted HTTP connections, and high-risk top-level domains (`.xyz`, `.top`, `.tk`, etc.).
  - Flags Punycode/IDN homograph attacks (e.g. `xn--appl-45a.com`) and spoofed subdomain chains.
  - Rejects dangerous schemes (`javascript:`, `file:`, `data:`).

### Tab 3: App Permission Audit (`modules/anomaly_detector.py`)
- **Isolation Forest Anomaly Detection**: Unsupervised model trained on baseline mobile application privilege profiles.
- Analyzes combinations of dangerous permissions (`has_sms_permission`, `overlay_permission`, `background_data_usage_mb`, `has_camera_permission`, `has_contacts_permission`).
- Flags over-privileged background apps and spyware outliers with explainable reasoning.
- Supports both demo datasets and custom CSV / JSON file uploads with built-in template downloads.

### Tab 4: Threat History & Logs (`database/supabase_client.py`)
- Persistent scan logs backed by Supabase PostgreSQL database with Row Level Security.
- **Fail-Safe Session Fallback**: If Supabase is not configured, logs are saved to an in-memory session buffer so the history dashboard is immediately usable in local and offline environments.
- Provides interactive filters by category, verdict distribution charts, and audit metrics.

---

## 🔒 Security & Privacy Features

1. **Automatic Credential Masking (`modules/security_utils.py`)**:
   - OTP codes, verification pins, credit card numbers, passwords, PAN, and Aadhaar numbers are automatically masked before any record is stored or displayed in history.
2. **URL Sanitization**:
   - Strips embedded credentials (`user:password@host`) and redacts sensitive query parameters (`token`, `auth`, `otp`, `password`).
3. **No Hardcoded Secrets**:
   - All external keys are managed through `.env` or Streamlit secrets (`.streamlit/secrets.toml`).
   - Automatically detects and ignores default placeholder credentials.
4. **File Upload Hardening**:
   - Validates magic byte signatures (PNG, JPEG, WEBP, BMP) to prevent file extension spoofing.
   - Enforces 10 MB image size limits and maximum pixel dimensions (8000px) to prevent decompression bomb attacks.
5. **Database Row Level Security (`database/schema.sql`)**:
   - Provides granular RLS policies for anonymous demo mode and production authenticated user mode (`auth.uid() = user_id`).

---

## 📁 Project Structure

```
cyber-ai/
├── app.py                      # Main Streamlit dashboard application
├── requirements.txt            # Python dependencies (Streamlit, PyTorch/Sklearn, OpenCV, etc.)
├── .env.example                # Template for environment configuration
├── .gitignore                  # Git exclusion rules
├── Dockerfile                  # Production container image definition with Tesseract OCR
├── .dockerignore               # Docker build exclusions
├── data/
│   ├── scam_messages.csv       # Training dataset for message scam classifier
│   └── mock_app_permissions.csv# Sample permissions dataset for app audit
├── database/
│   ├── __init__.py
│   ├── schema.sql              # Supabase PostgreSQL DDL with RLS policies
│   └── supabase_client.py      # Resilient Supabase database connector
├── models/
│   └── scam_model.joblib       # Cached trained NLP model
├── modules/
│   ├── __init__.py
│   ├── anomaly_detector.py     # Isolation Forest app permission analyzer
│   ├── nlp_analyzer.py         # Message scam analyzer
│   ├── ocr_scanner.py          # Payment receipt scanner & ELA forensics
│   ├── security_utils.py       # Data masking, sanitization, and upload validation
│   └── url_scanner.py          # URL security heuristics & VirusTotal client
└── tests/
    ├── __init__.py
    ├── test_anomaly_detector.py# Unit tests for app anomaly detector
    ├── test_nlp_analyzer.py    # Unit tests for message analyzer
    ├── test_ocr_scanner.py     # Unit tests for OCR & image forensics
    ├── test_security_utils.py  # Unit tests for sanitization & redaction
    ├── test_supabase_client.py # Unit tests for database client
    └── test_url_scanner.py     # Unit tests for URL scanner
```

---

## 💻 Local Quickstart

### 1. Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Git

### 2. Setup Virtual Environment
```bash
# Clone the repository
git clone <your-repository-url>
cd cyber-ai

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Launch the Application
```bash
python -m streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

| Variable | Required | Default / Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | Optional | Free API key from [VirusTotal](https://www.virustotal.com/). If omitted, offline heuristics mode is used. |
| `SUPABASE_URL` | Optional | Project URL from [Supabase](https://supabase.com/). If omitted, in-memory session logs are used. |
| `SUPABASE_KEY` | Optional | Anon public API key from Supabase. |
| `TESSERACT_CMD` | Optional | Full path to `tesseract.exe` on Windows (e.g., `C:\Program Files\Tesseract-OCR\tesseract.exe`). |

---

## 🔤 Tesseract OCR Setup

### Windows
1. Download and run the 64-bit installer from [UB-Mannheim Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki).
2. Install to the default directory: `C:\Program Files\Tesseract-OCR`.
3. Add `TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe` to your `.env` file, or add the directory to your system `PATH`.

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y tesseract-ocr tesseract-ocr-eng
```

### macOS (Homebrew)
```bash
brew install tesseract
```

*(Note: When running via Docker, Tesseract OCR is installed and pre-configured automatically!)*

---

## 🧪 Automated Testing

Run the full automated test suite using `pytest`:
```bash
python -m pytest -v
```

All 49 unit tests verify:
- Message classification (scams, lotteries, KYC threats, benign texts)
- URL normalization, protocol restrictions, offline heuristics, and mocked VirusTotal API flows
- Image decoding, validation, ELA tampering checks, and missing Tesseract fallbacks
- Device app permission anomaly scoring, CSV/JSON loaders, and boolean handling
- Supabase client fail-soft behavior, local buffering, and token masking
- Sensitive data redaction for credit cards, OTPs, Aadhaar, PAN, and credentials

---

## 🐳 Docker Deployment

The included `Dockerfile` packages Python 3.11, Tesseract OCR with English language data, OpenCV runtime libraries, and security configurations.

### Build and Run with Docker
```bash
# Build the container image
docker build -t fraud-guard-ai .

# Run the container
docker run -p 8501:8501 --env-file .env fraud-guard-ai
```

Access the app in your browser at `http://localhost:8501`.

---

## ☁️ Cloud Deployment Guides

### Option 1: Streamlit Community Cloud (Quickest)
1. Push this repository to GitHub.
2. Visit [share.streamlit.io](https://share.streamlit.io/) and click **New app**.
3. Select your repository, branch, and set main file to `app.py`.
4. Add `packages.txt` with:
   ```
   tesseract-ocr
   tesseract-ocr-eng
   libgl1
   ```
5. In App Settings -> Secrets, paste your environment variables:
   ```toml
   VIRUSTOTAL_API_KEY = "your_actual_key"
   SUPABASE_URL = "https://your-project.supabase.co"
   SUPABASE_KEY = "your_actual_anon_key"
   ```

### Option 2: Render / Railway / Google Cloud Run (Container Deployment)
1. Deploy using the provided `Dockerfile`.
2. Set container port to `8501`.
3. Configure environment variables in the provider dashboard (`VIRUSTOTAL_API_KEY`, `SUPABASE_URL`, `SUPABASE_KEY`).

### Option 3: Supabase Cloud Database Setup
1. Log in to [Supabase](https://supabase.com/) and create a new project.
2. Go to **SQL Editor** -> **New query**.
3. Copy and run the contents of [`database/schema.sql`](database/schema.sql).
4. Copy your project URL and anon public key into your environment variables.

---

## ⚠️ Known Limitations & Disclaimers

1. **AI Heuristic Predictions**:
   - All verdicts (Safe, Warning, High Risk, Clean, Suspicious) are automated statistical predictions and pattern analyses. They do not constitute formal legal or financial proof of fraud.
2. **Screenshot Verification Rule**:
   - Digital receipts can be generated or spoofed with varying degrees of fidelity. Users should always cross-reference payments inside their authorized bank or UPI mobile application.
3. **VirusTotal Rate Limits**:
   - The free VirusTotal public API key is limited to 4 requests per minute and 500 requests per day. The application gracefully catches 429 errors and falls back to local heuristics.
4. **Production Authentication**:
   - For public multi-tenant production deployments, enable Supabase Auth and activate the user-specific RLS policies provided in [`database/schema.sql`](database/schema.sql).
