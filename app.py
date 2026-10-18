"""
Digital Fraud & Threat Defense Guard - Streamlit Dashboard.

Four integrated defense tabs:
1. Message & Payment Analyzer (NLP message scam detection & Payment receipt forensics)
2. URL & Phishing Link Checker (VirusTotal intelligence & Offline structural heuristics)
3. App Permission Audit (Isolation Forest anomaly detection on device apps)
4. Threat History & Logs (Cloud Supabase logging with local session fallback)

Run locally with:
    streamlit run app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from database import supabase_client as db
from modules import anomaly_detector, nlp_analyzer, ocr_scanner, security_utils, url_scanner

# --------------------------------------------------------------------------- #
# Page Configuration & Styling
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title="Digital Fraud & Threat Defense Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

VERDICT_STYLE = {
    "Safe": ("#1b7f3b", "✅"),
    "Clean": ("#1b7f3b", "✅"),
    "Warning": ("#b7791f", "⚠️"),
    "Suspicious": ("#b7791f", "⚠️"),
    "Unknown": ("#4a5568", "❔"),
    "High Risk": ("#c53030", "🚨"),
    "Malicious": ("#c53030", "🚨"),
}

st.markdown(
    """
    <style>
    .verdict-box {
        padding: 1.1rem 1.4rem;
        border-radius: 12px;
        color: #ffffff;
        margin: 0.75rem 0 1.25rem 0;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    .verdict-box h3 { margin: 0; color: #ffffff !important; font-weight: 700; }
    .verdict-box p { margin: 0.35rem 0 0 0; opacity: 0.95; font-size: 0.95rem; }
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        border-radius: 6px;
        font-size: 0.82rem;
        font-weight: 600;
    }
    .stProgress > div > div > div > div {
        border-radius: 8px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def verdict_banner(verdict: str, subtitle: str = "", disclaimer: str = "") -> None:
    """Render a prominent, accessible verdict banner with an optional AI disclaimer."""
    color, icon = VERDICT_STYLE.get(verdict, ("#4a5568", "ℹ️"))
    disclaimer_html = f'<p style="font-size:0.8rem; margin-top:0.4rem; opacity:0.85;"><em>ℹ️ {disclaimer}</em></p>' if disclaimer else ""
    st.markdown(
        f"""
        <div class="verdict-box" style="background-color: {color};">
            <h3>{icon} {verdict}</h3>
            <p>{subtitle}</p>
            {disclaimer_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def log_scan_safely(input_type: str, content: str, verdict: str, confidence=None, details=None) -> None:
    """Save scan to history (Supabase or local session) with automatic redaction notice."""
    ok, msg = db.save_scan(input_type, content, verdict, confidence, details)
    if ok:
        st.caption(f"🔒 **Privacy Protected**: Sensitive tokens redacted. ({msg})")
    else:
        st.caption(f"ℹ️ History status: {msg}")


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.title("🛡️ Defense Guard")
    st.caption("AI-powered digital fraud & threat defense system")
    st.divider()

    st.subheader("System Status")
    vt_active = url_scanner.is_virustotal_configured()
    st.markdown(
        f"**VirusTotal API:** {'🟢 Configured' if vt_active else '🟡 Offline Heuristics (Key missing)'}"
    )

    db_active = db.is_configured()
    st.markdown(
        f"**Database:** {'🟢 Cloud (Supabase)' if db_active else '🟡 In-Memory Session Logs'}"
    )

    ocr_active = ocr_scanner.is_tesseract_available()
    st.markdown(
        f"**OCR Engine:** {'🟢 Tesseract Ready' if ocr_active else '🟡 Forensics Only (Tesseract missing)'}"
    )

    st.divider()

    with st.expander("ℹ️ About & Security"):
        st.markdown(
            """
            - **Privacy First**: OTPs, passwords, and card numbers are masked prior to logging.
            - **Predictive AI**: Results are probabilistic pattern evaluations, not legal or financial proof.
            - **Verification Rule**: Always verify transactions directly in your official banking application.
            """
        )

    with st.expander("⚙️ Tesseract OCR Setup"):
        st.markdown(
            """
            - **Windows**: Install [UB-Mannheim Tesseract](https://github.com/UB-Mannheim/tesseract/wiki), set `TESSERACT_CMD` in `.env`.
            - **Linux/Docker**: `apt-get install -y tesseract-ocr` (included in Dockerfile).
            """
        )


# --------------------------------------------------------------------------- #
# Main Layout
# --------------------------------------------------------------------------- #
st.title("🛡️ Digital Fraud & Threat Defense Guard")
st.markdown(
    "Automated cyber defense suite for analyzing phishing messages, manipulated payment receipts, "
    "malicious URLs, and anomalous app permissions."
)

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "💬 Message & Payment Analyzer",
        "🔗 URL & Phishing Link Checker",
        "📱 App Permission Audit",
        "🗂️ Threat History & Logs",
    ]
)


# =========================================================================== #
# TAB 1: Message and Payment Analyzer
# =========================================================================== #
with tab1:
    left_col, right_col = st.columns(2, gap="large")

    # --- Left Column: SMS & Message Scam Analyzer ---
    with left_col:
        st.subheader("💬 Message Scam Analyzer")
        st.caption("Inspect SMS, WhatsApp texts, or emails for social engineering and fraud patterns.")

        # Sample quick loaders
        sample_choice = st.selectbox(
            "Load a test sample:",
            [
                "Custom input...",
                "Scam: Urgent Bank KYC Deactivation",
                "Scam: Lottery Winner Advance Fee",
                "Scam: Remote Desktop / AnyDesk Request",
                "Legitimate: Normal Bank Debit Notification",
                "Legitimate: Friendly Chat",
            ],
            key="nlp_sample_selector",
        )

        default_text = ""
        if sample_choice == "Scam: Urgent Bank KYC Deactivation":
            default_text = "URGENT: Your SBI net banking is deactivated! Update your KYC within 24 hours to avoid penalty. Share OTP at http://sbi-kyc-verify.xyz"
        elif sample_choice == "Scam: Lottery Winner Advance Fee":
            default_text = "Congratulations! You have won a lottery of Rs 25,00,000 in lucky draw. Transfer Rs 2,500 registration fee to claim prize."
        elif sample_choice == "Scam: Remote Desktop / AnyDesk Request":
            default_text = "Customer care refund alert: Install AnyDesk app immediately and share code to receive your pending electricity cashback."
        elif sample_choice == "Legitimate: Normal Bank Debit Notification":
            default_text = "Rs 850.00 debited from account ending 4821 at Amazon. Available balance Rs 14,200. Do not share your OTP with anyone."
        elif sample_choice == "Legitimate: Friendly Chat":
            default_text = "Hi Rahul, are we still meeting tomorrow for coffee around 4 PM?"

        msg_input = st.text_area(
            "Message text to analyze:",
            value=default_text,
            height=160,
            placeholder="Paste text here...",
            key="msg_input_area",
        )

        if st.button("Analyze Message", type="primary", key="btn_analyze_msg"):
            if not msg_input or not msg_input.strip():
                st.warning("Please enter or paste a message to analyze.")
            else:
                try:
                    with st.spinner("Analyzing message patterns..."):
                        res = nlp_analyzer.analyze_text(msg_input)

                    verdict_banner(
                        res["verdict"],
                        f"Risk Score: {res['risk_score']:.1%} · Confidence: {res['confidence']:.1%} · Engine: {res['method']}",
                        res["disclaimer"],
                    )

                    st.markdown("**Scam Probability Gauge:**")
                    st.progress(res["risk_score"])

                    if res["flags"]:
                        st.markdown("**Identified Scam Signals:**")
                        for flag in res["flags"]:
                            kw_list = ", ".join(f"`{k}`" for k in flag["keywords"])
                            st.markdown(f"- 🚩 **{flag['category']}**: {kw_list}")

                        st.markdown("**Highlighted Pattern Preview:**")
                        st.info(res["highlighted"])
                    else:
                        st.success("✅ No suspicious keywords or social engineering triggers detected.")

                    log_scan_safely(
                        input_type="text",
                        content=msg_input,
                        verdict=res["verdict"],
                        confidence=res["confidence"],
                        details={
                            "risk_score": res["risk_score"],
                            "flags": res["flags"],
                            "method": res["method"],
                        },
                    )

                except ValueError as exc:
                    st.warning(str(exc))
                except Exception as exc:
                    st.error(f"Analysis error: {exc}")

    # --- Right Column: Payment Screenshot Forensics ---
    with right_col:
        st.subheader("🧾 Payment Receipt Integrity")
        st.caption("Verify UPI payment screenshots for tampering, fake receipts, and metadata anomalies.")

        if not ocr_scanner.is_tesseract_available():
            st.info(
                "ℹ️ **Notice**: Tesseract OCR engine is not installed locally. "
                "The scanner will perform **Error Level Analysis (ELA)** and **Metadata Tampering Forensics**."
            )

        uploaded_img = st.file_uploader(
            "Upload screenshot (PNG, JPG, WEBP):",
            type=["png", "jpg", "jpeg", "webp"],
            key="payment_screenshot_uploader",
        )

        if uploaded_img is not None:
            st.image(uploaded_img, caption=f"Uploaded: {uploaded_img.name}", width=280)

        if st.button("Scan Screenshot", type="primary", key="btn_scan_receipt"):
            if uploaded_img is None:
                st.warning("Please upload a receipt image first.")
            else:
                try:
                    img_bytes = uploaded_img.getvalue()
                    with st.spinner("Analyzing image structure and forensics..."):
                        res = ocr_scanner.scan_payment_image(img_bytes)

                    val = res["validation"]
                    fields = res["fields"]

                    verdict_banner(
                        val["verdict"],
                        f"Risk Points: {val['risk_points']} · Confidence: {val['confidence']:.1%}",
                        val.get("disclaimer", ""),
                    )

                    # Show extracted fields if OCR was active
                    if res.get("ocr_available", True):
                        st.markdown("**Extracted Transaction Fields:**")
                        display_fields = {
                            k: v for k, v in fields.items() if not k.startswith("all_")
                        }
                        df_fields = (
                            pd.DataFrame([display_fields])
                            .T.rename(columns={0: "Value"})
                            .fillna("Not detected")
                        )
                        st.table(df_fields)
                    else:
                        st.caption("ℹ️ Field extraction skipped (Tesseract not installed).")

                    # Red flags
                    if val["red_flags"]:
                        st.markdown("**Forensic Red Flags:**")
                        for rf in val["red_flags"]:
                            st.markdown(f"- 🚩 {rf}")

                    # Notes
                    if val["notes"]:
                        for note in val["notes"]:
                            st.caption(f"ℹ️ {note}")

                    # Raw OCR expander
                    if res.get("ocr_available", False) and res.get("extracted_text"):
                        with st.expander("View Raw OCR Text"):
                            st.text(res["extracted_text"])

                    log_scan_safely(
                        input_type="image",
                        content=f"Screenshot: {uploaded_img.name}",
                        verdict=val["verdict"],
                        confidence=val["confidence"],
                        details={
                            "risk_points": val["risk_points"],
                            "red_flags": val["red_flags"],
                            "ela": val.get("ela"),
                        },
                    )

                except ocr_scanner.OCRScannerError as exc:
                    st.error(str(exc))
                except Exception as exc:
                    st.error(f"Image analysis error: {exc}")


# =========================================================================== #
# TAB 2: URL & Phishing Link Checker
# =========================================================================== #
with tab2:
    st.subheader("🔗 URL & Phishing Link Checker")
    st.caption("Multi-layered link verification combining local structural heuristics with VirusTotal vendor intelligence.")

    url_col1, url_col2 = st.columns([3, 1])
    with url_col1:
        url_preset = st.selectbox(
            "Select a test URL:",
            [
                "Custom URL...",
                "Phishing: IP address host with login path",
                "Phishing: Punycode / IDN lookalike domain",
                "Phishing: Suspicious free TLD (.xyz) with KYC keywords",
                "Legitimate: Official Google website",
                "Legitimate: Official GitHub repository",
            ],
            key="url_preset_selector",
        )

    preset_url_val = ""
    if url_preset == "Phishing: IP address host with login path":
        preset_url_val = "http://192.168.1.105/bank-login/verify.php"
    elif url_preset == "Phishing: Punycode / IDN lookalike domain":
        preset_url_val = "https://xn--appl-45a.com/account-recovery"
    elif url_preset == "Phishing: Suspicious free TLD (.xyz) with KYC keywords":
        preset_url_val = "http://secure-update-kyc.sbi-alert.xyz/auth?token=99281"
    elif url_preset == "Legitimate: Official Google website":
        preset_url_val = "https://www.google.com"
    elif url_preset == "Legitimate: Official GitHub repository":
        preset_url_val = "https://github.com"

    url_target = st.text_input(
        "Enter destination URL to verify:",
        value=preset_url_val,
        placeholder="https://example.com/login",
        key="url_target_input",
    )

    if st.button("Scan URL", type="primary", key="btn_scan_url"):
        if not url_target or not url_target.strip():
            st.warning("Please enter a URL to check.")
        else:
            try:
                with st.spinner("Analyzing URL structure and reputation..."):
                    analysis = url_scanner.analyze_url(url_target)

                heur = analysis["heuristics"]
                vt = analysis["virustotal"]
                verdict = analysis["verdict"]

                verdict_banner(
                    verdict,
                    f"Target: `{analysis['normalized_url']}` · Analysis: {analysis['assessment_type']}",
                    "URL analysis evaluates structural risk markers and threat databases. Always confirm the exact browser address bar before signing in.",
                )

                # Show VirusTotal metrics if available
                if vt:
                    st.markdown("**VirusTotal Threat Intelligence Summary:**")
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Malicious", vt["malicious"], delta=None)
                    m2.metric("Suspicious", vt["suspicious"], delta=None)
                    m3.metric("Harmless", vt["harmless"], delta=None)
                    m4.metric("Engines Scanned", vt["total_engines"])

                    if vt["flagged_vendors"]:
                        st.markdown("**Security Vendors Flagging This Link:**")
                        st.dataframe(pd.DataFrame(vt["flagged_vendors"]), width="stretch", hide_index=True)
                else:
                    st.info(f"ℹ️ {analysis['vt_error']}")

                # Local heuristics notes
                st.markdown("**Local Structural Heuristics:**")
                if heur["notes"]:
                    for n in heur["notes"]:
                        st.markdown(f"- ⚠️ {n}")
                else:
                    st.success("✅ No suspicious structural markers (IP host, punycode, unusual TLD) detected.")

                log_scan_safely(
                    input_type="url",
                    content=analysis["normalized_url"],
                    verdict=verdict,
                    confidence=None,
                    details={
                        "heuristics": heur["notes"],
                        "virustotal": {
                            "malicious": vt["malicious"],
                            "suspicious": vt["suspicious"],
                            "total": vt["total_engines"],
                        }
                        if vt
                        else None,
                    },
                )

            except url_scanner.URLScannerError as exc:
                st.warning(str(exc))
            except Exception as exc:
                st.error(f"URL analysis error: {exc}")


# =========================================================================== #
# TAB 3: App Permission Audit
# =========================================================================== #
with tab3:
    st.subheader("📱 Device App Permission Audit")
    st.caption("Audit installed applications using Isolation Forest anomaly detection to spot rogue spyware and over-privileged software.")

    st.markdown(
        """
        Required data format columns:
        `app_name`, `has_sms_permission`, `has_camera_permission`, `has_contacts_permission`, `background_data_usage_mb`, `overlay_permission`
        """
    )

    data_mode = st.radio(
        "Choose audit dataset:",
        ["Built-in Demonstration List", "Upload Custom CSV / JSON"],
        horizontal=True,
        key="app_audit_mode_radio",
    )

    app_data_df: pd.DataFrame | None = None

    if data_mode == "Upload Custom CSV / JSON":
        uploaded_app_file = st.file_uploader(
            "Upload app permission export (CSV or JSON):",
            type=["csv", "json"],
            key="app_file_uploader",
        )
        if uploaded_app_file is not None:
            try:
                app_data_df = anomaly_detector.load_app_data(uploaded_app_file, uploaded_app_file.name)
                st.success(f"Loaded {len(app_data_df)} application records from `{uploaded_app_file.name}`.")
            except Exception as exc:
                st.error(f"File loading error: {exc}")
    else:
        app_data_df = anomaly_detector.build_mock_app_list()
        with st.expander("Preview Demonstration Data (15 apps)"):
            st.dataframe(app_data_df, width="stretch", hide_index=True)

    # Template download helper
    mock_csv_bytes = anomaly_detector.build_mock_app_list().to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Download Sample CSV Template",
        data=mock_csv_bytes,
        file_name="sample_app_permissions.csv",
        mime="text/csv",
        key="btn_download_sample_csv",
    )

    if st.button("Run Anomaly Audit", type="primary", key="btn_run_app_audit"):
        if app_data_df is None or app_data_df.empty:
            st.warning("Please upload a valid CSV/JSON file or select the built-in demonstration list.")
        else:
            try:
                with st.spinner("Evaluating permission distributions and background activity..."):
                    audit_res = anomaly_detector.analyze_apps(app_data_df)

                summary = audit_res["summary"]
                results_df = audit_res["results"]

                verdict_banner(
                    summary["verdict"],
                    f"Audited {summary['total_apps']} apps · {summary['high_risk']} High Risk · {summary['warning']} Warning · {summary['safe']} Safe",
                    summary.get("disclaimer", ""),
                )

                a1, a2, a3 = st.columns(3)
                a1.metric("High Risk Anomalies", summary["high_risk"])
                a2.metric("Borderline Warnings", summary["warning"])
                a3.metric("Normal Apps", summary["safe"])

                st.markdown("**Audit Details by Application:**")
                st.dataframe(
                    results_df[
                        [
                            "app_name",
                            "risk_level",
                            "anomaly_score",
                            "reason",
                            "has_sms_permission",
                            "overlay_permission",
                            "background_data_usage_mb",
                        ]
                    ],
                    width="stretch",
                    hide_index=True,
                )

                # Flagged apps list for logging
                flagged_names = results_df[results_df["risk_level"] != "Safe"]["app_name"].tolist()
                log_scan_safely(
                    input_type="app_audit",
                    content=f"Audited {summary['total_apps']} apps (Flagged: {len(flagged_names)})",
                    verdict=summary["verdict"],
                    confidence=None,
                    details={"summary": summary, "flagged_apps": flagged_names[:20]},
                )

            except Exception as exc:
                st.error(f"Audit failure: {exc}")


# =========================================================================== #
# TAB 4: Threat History & Logs
# =========================================================================== #
with tab4:
    st.subheader("🗂️ Threat History & Scan Logs")
    st.caption("Review past threat assessments, verify privacy redactions, and inspect audit trails.")

    hist_col1, hist_col2, hist_col3 = st.columns([2, 1, 1])
    with hist_col1:
        type_choice = st.selectbox(
            "Filter by category:",
            ["All Categories", "text", "image", "url", "app_audit"],
            key="hist_category_selector",
        )
    with hist_col2:
        limit_count = st.number_input("Max records:", min_value=10, max_value=200, value=50, step=10)
    with hist_col3:
        st.write("")
        st.write("")
        refresh_btn = st.button("🔄 Refresh Logs", key="btn_refresh_logs")

    filter_type = None if type_choice == "All Categories" else type_choice
    rows, note_msg = db.fetch_history(limit=limit_count, input_type=filter_type)

    if note_msg:
        st.info(note_msg)

    if not rows:
        st.write("No scan records found. Run an analysis in any tab to record logs.")
    else:
        df_hist = pd.DataFrame(rows)

        # Metrics cards
        high_risk_scans = int((df_hist["verdict"].isin(["High Risk", "Malicious"])).sum())
        clean_scans = int((df_hist["verdict"].isin(["Safe", "Clean"])).sum())

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Scans Shown", len(df_hist))
        c2.metric("High Risk Detections", high_risk_scans)
        c3.metric("Clean / Safe Scans", clean_scans)

        # Chart
        st.markdown("**Verdicts Distribution:**")
        verdict_counts = df_hist["verdict"].value_counts()
        st.bar_chart(verdict_counts)

        # Log table
        cols_to_show = [
            c for c in ["created_at", "input_type", "content", "verdict", "confidence"]
            if c in df_hist.columns
        ]
        st.markdown("**Recent Scan Records:**")
        st.dataframe(df_hist[cols_to_show], width="stretch", hide_index=True)
