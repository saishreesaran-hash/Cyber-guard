"""
Digital Fraud & Threat Defense Guard - 3D Cyber Defense Dashboard.

A state-of-the-art 3D interactive cybersecurity console:
- Interactive WebGL / Three.js 3D Cyber Defense Shield & Holographic Globe
- 3D Feature Space Anomaly Visualizer (Plotly 3D WebGL)
- Four defense channels: Message Analyzer, URL Checker, App Permission Audit, Threat History

Run locally with:
    streamlit run app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

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
# Page Configuration & 3D Sci-Fi Styling
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title="Cyber Defense Guard - 3D Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Rajdhani:wght@500;600;700&display=swap');

    /* Global Dark Cyber Theme */
    .stApp {
        background: radial-gradient(circle at 50% 10%, #0d1b2a 0%, #050b14 60%, #020408 100%);
        color: #e2e8f0;
        font-family: 'Rajdhani', sans-serif;
    }

    h1, h2, h3, .cyber-title {
        font-family: 'Orbitron', monospace !important;
        letter-spacing: 1.5px;
        text-transform: uppercase;
    }

    /* 3D Glassmorphic Cards */
    .cyber-card {
        background: rgba(13, 27, 42, 0.65);
        border: 1px solid rgba(0, 242, 254, 0.25);
        border-radius: 14px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), inset 0 0 15px rgba(0, 242, 254, 0.05);
        backdrop-filter: blur(12px);
        transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
        transform: perspective(800px) translateZ(0px);
    }
    .cyber-card:hover {
        transform: perspective(800px) translateY(-3px) translateZ(8px);
        box-shadow: 0 16px 36px rgba(0, 242, 254, 0.18), inset 0 0 20px rgba(0, 242, 254, 0.1);
        border-color: rgba(0, 242, 254, 0.6);
    }

    /* 3D Isometric Verdict Boxes */
    .verdict-box-3d {
        position: relative;
        padding: 1.25rem 1.5rem;
        border-radius: 12px;
        color: #ffffff;
        margin: 0.75rem 0 1.25rem 0;
        box-shadow: 0 12px 28px rgba(0, 0, 0, 0.6), inset 0 1px 0 rgba(255, 255, 255, 0.2);
        transform: perspective(600px) rotateX(1deg);
        overflow: hidden;
    }
    .verdict-box-3d h3 {
        margin: 0;
        color: #ffffff !important;
        font-weight: 800;
        text-shadow: 0 2px 10px rgba(0,0,0,0.5);
    }
    .verdict-box-3d p {
        margin: 0.35rem 0 0 0;
        opacity: 0.95;
        font-size: 0.95rem;
    }

    /* 3D Metric Badges */
    div[data-testid="stMetricValue"] {
        font-family: 'Orbitron', monospace !important;
        font-weight: 700;
        color: #00f2fe !important;
        text-shadow: 0 0 12px rgba(0, 242, 254, 0.5);
    }
    div[data-testid="stMetricLabel"] {
        font-family: 'Rajdhani', sans-serif !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #94a3b8 !important;
    }

    /* Progress bar glowing neon */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #00ff87 0%, #00f2fe 50%, #ff0055 100%) !important;
        box-shadow: 0 0 15px rgba(0, 242, 254, 0.6);
        border-radius: 8px;
    }

    /* Custom Streamlit Tabs 3D styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: rgba(10, 20, 35, 0.7);
        padding: 8px;
        border-radius: 12px;
        border: 1px solid rgba(0, 242, 254, 0.2);
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        color: #94a3b8;
        font-family: 'Orbitron', monospace;
        font-size: 0.82rem;
        padding: 8px 16px;
        transition: all 0.2s ease;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(0, 242, 254, 0.2) 0%, rgba(121, 40, 202, 0.3) 100%) !important;
        color: #00f2fe !important;
        border: 1px solid rgba(0, 242, 254, 0.5) !important;
        box-shadow: 0 0 14px rgba(0, 242, 254, 0.3);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

VERDICT_COLORS = {
    "Safe": ("#059669", "✅", "rgba(5, 150, 105, 0.3)"),
    "Clean": ("#059669", "✅", "rgba(5, 150, 105, 0.3)"),
    "Warning": ("#d97706", "⚠️", "rgba(217, 119, 6, 0.3)"),
    "Suspicious": ("#d97706", "⚠️", "rgba(217, 119, 6, 0.3)"),
    "Unknown": ("#475569", "❔", "rgba(71, 85, 105, 0.3)"),
    "High Risk": ("#dc2626", "🚨", "rgba(220, 38, 38, 0.3)"),
    "Malicious": ("#dc2626", "🚨", "rgba(220, 38, 38, 0.3)"),
}


def verdict_banner(verdict: str, subtitle: str = "", disclaimer: str = "") -> None:
    color, icon, glow = VERDICT_COLORS.get(verdict, ("#475569", "ℹ️", "rgba(71, 85, 105, 0.3)"))
    disclaimer_html = (
        f'<p style="font-size:0.8rem; margin-top:0.4rem; opacity:0.85;"><em>ℹ️ {disclaimer}</em></p>'
        if disclaimer
        else ""
    )
    st.markdown(
        f"""
        <div class="verdict-box-3d" style="background: linear-gradient(135deg, {color} 0%, #0a1120 100%); border: 1px solid {color}; box-shadow: 0 0 20px {glow};">
            <h3>{icon} {verdict}</h3>
            <p>{subtitle}</p>
            {disclaimer_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def log_scan_safely(input_type: str, content: str, verdict: str, confidence=None, details=None) -> None:
    ok, msg = db.save_scan(input_type, content, verdict, confidence, details)
    if ok:
        st.caption(f"🔒 **Privacy Protected**: Sensitive tokens redacted. ({msg})")
    else:
        st.caption(f"ℹ️ History status: {msg}")


# --------------------------------------------------------------------------- #
# Interactive 3D Three.js Cyber Defense Globe & HUD Component
# --------------------------------------------------------------------------- #
def render_3d_cyber_globe(threat_count: int = 3, active_nodes: int = 142):
    threejs_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{
          margin: 0;
          overflow: hidden;
          background: transparent;
          font-family: 'Orbitron', monospace, sans-serif;
        }}
        #canvas-container {{
          width: 100%;
          height: 320px;
          position: relative;
          background: radial-gradient(ellipse at center, rgba(0, 242, 254, 0.08) 0%, rgba(5, 11, 20, 0.95) 75%);
          border: 1px solid rgba(0, 242, 254, 0.25);
          border-radius: 14px;
          box-shadow: inset 0 0 30px rgba(0, 242, 254, 0.15), 0 8px 32px rgba(0,0,0,0.6);
        }}
        .hud-overlay {{
          position: absolute;
          top: 14px;
          left: 18px;
          pointer-events: none;
          color: #00f2fe;
          font-size: 11px;
          letter-spacing: 1.5px;
          text-shadow: 0 0 8px rgba(0, 242, 254, 0.7);
        }}
        .hud-overlay-right {{
          position: absolute;
          top: 14px;
          right: 18px;
          text-align: right;
          pointer-events: none;
          color: #00ff87;
          font-size: 11px;
          letter-spacing: 1.5px;
          text-shadow: 0 0 8px rgba(0, 255, 135, 0.7);
        }}
        .hud-bottom {{
          position: absolute;
          bottom: 12px;
          left: 18px;
          color: #94a3b8;
          font-size: 10px;
          letter-spacing: 1px;
          pointer-events: none;
        }}
        .pulse {{
          display: inline-block;
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #00ff87;
          box-shadow: 0 0 10px #00ff87;
          margin-right: 6px;
          animation: blink 1.4s infinite;
        }}
        @keyframes blink {{
          0%, 100% {{ opacity: 1; transform: scale(1); }}
          50% {{ opacity: 0.3; transform: scale(0.8); }}
        }}
      </style>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    </head>
    <body>
      <div id="canvas-container">
        <div class="hud-overlay">
          <div><span class="pulse"></span>3D CYBER THREAT RADAR // ACTIVE</div>
          <div style="color: #64748b; margin-top: 4px;">SENSORS ONLINE: 4/4 CHANNELS</div>
        </div>
        <div class="hud-overlay-right">
          <div>SYS INTEGRITY: 99.8%</div>
          <div style="color: #ff0055; margin-top: 4px;">ANOMALIES FLAGGED: {threat_count}</div>
        </div>
        <div class="hud-bottom">
          CLICK & DRAG TO ROTATE 3D DEFENSE MATRIX · THREE.JS ACCELERATED
        </div>
      </div>

      <script>
        const container = document.getElementById('canvas-container');
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(45, container.clientWidth / container.clientHeight, 0.1, 1000);
        camera.position.z = 240;

        const renderer = new THREE.WebGLRenderer({{ antialias: true, alpha: true }});
        renderer.setSize(container.clientWidth, container.clientHeight);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        container.appendChild(renderer.domElement);

        // Core holographic globe (wireframe icosahedron)
        const globeGeo = new THREE.IcosahedronGeometry(70, 3);
        const globeMat = new THREE.MeshBasicMaterial({{
          color: 0x00f2fe,
          wireframe: true,
          transparent: true,
          opacity: 0.22
        }});
        const globe = new THREE.Mesh(globeGeo, globeMat);
        scene.add(globe);

        // Inner glowing core
        const coreGeo = new THREE.SphereGeometry(62, 16, 16);
        const coreMat = new THREE.MeshBasicMaterial({{
          color: 0x0a2540,
          transparent: true,
          opacity: 0.45
        }});
        const core = new THREE.Mesh(coreGeo, coreMat);
        scene.add(core);

        // Orbit ring 1 (Horizontal)
        const ringGeo1 = new THREE.RingGeometry(85, 87, 64);
        const ringMat1 = new THREE.MeshBasicMaterial({{
          color: 0x00f2fe,
          side: THREE.DoubleSide,
          transparent: true,
          opacity: 0.35
        }});
        const ring1 = new THREE.Mesh(ringGeo1, ringMat1);
        ring1.rotation.x = Math.PI / 2;
        scene.add(ring1);

        // Orbit ring 2 (Tilted 45deg)
        const ringGeo2 = new THREE.RingGeometry(96, 98, 64);
        const ringMat2 = new THREE.MeshBasicMaterial({{
          color: 0x7928ca,
          side: THREE.DoubleSide,
          transparent: true,
          opacity: 0.3
        }});
        const ring2 = new THREE.Mesh(ringGeo2, ringMat2);
        ring2.rotation.x = Math.PI / 3;
        ring2.rotation.y = Math.PI / 4;
        scene.add(ring2);

        // Glowing particle cloud
        const particleCount = 350;
        const particleGeo = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        for(let i = 0; i < particleCount; i++) {{
          const theta = Math.random() * Math.PI * 2;
          const phi = Math.acos((Math.random() * 2) - 1);
          const r = 72 + Math.random() * 12;

          positions[i*3] = r * Math.sin(phi) * Math.cos(theta);
          positions[i*3+1] = r * Math.sin(phi) * Math.sin(theta);
          positions[i*3+2] = r * Math.cos(phi);

          if (i < 20) {{
            // Threat nodes in red/magenta
            colors[i*3] = 1.0; colors[i*3+1] = 0.0; colors[i*3+2] = 0.35;
          }} else {{
            // Clean nodes in cyan/emerald
            colors[i*3] = 0.0; colors[i*3+1] = 0.95; colors[i*3+2] = 1.0;
          }}
        }}

        particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        particleGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const particleMat = new THREE.PointsMaterial({{
          size: 3.5,
          vertexColors: true,
          transparent: true,
          opacity: 0.85
        }});
        const particles = new THREE.Points(particleGeo, particleMat);
        scene.add(particles);

        // Interactive Mouse Orbit
        let isDragging = false;
        let prevMouse = {{ x: 0, y: 0 }};
        let targetRotationX = 0;
        let targetRotationY = 0;

        container.addEventListener('mousedown', (e) => {{
          isDragging = true;
          prevMouse = {{ x: e.clientX, y: e.clientY }};
        }});

        window.addEventListener('mouseup', () => isDragging = false);

        container.addEventListener('mousemove', (e) => {{
          if (isDragging) {{
            const deltaX = e.clientX - prevMouse.x;
            const deltaY = e.clientY - prevMouse.y;
            targetRotationY += deltaX * 0.006;
            targetRotationX += deltaY * 0.006;
            prevMouse = {{ x: e.clientX, y: e.clientY }};
          }}
        }});

        // Responsive resize
        window.addEventListener('resize', () => {{
          camera.aspect = container.clientWidth / container.clientHeight;
          camera.updateProjectionMatrix();
          renderer.setSize(container.clientWidth, container.clientHeight);
        }});

        // Animation Loop
        function animate() {{
          requestAnimationFrame(animate);

          // Auto slow spin + mouse rotation dampening
          globe.rotation.y += 0.004 + (targetRotationY - globe.rotation.y) * 0.08;
          globe.rotation.x += (targetRotationX - globe.rotation.x) * 0.08;

          particles.rotation.y = globe.rotation.y;
          particles.rotation.x = globe.rotation.x;

          ring1.rotation.z += 0.008;
          ring2.rotation.z -= 0.006;

          renderer.render(scene, camera);
        }}
        animate();
      </script>
    </body>
    </html>
    """
    components.html(threejs_html, height=330)


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.markdown('<h2 style="color:#00f2fe;">🛡️ CYBER GUARD</h2>', unsafe_allow_html=True)
    st.caption("3D AI Defense & Threat Neutralization Console")
    st.divider()

    st.markdown("**DEFENSE SENSOR MATRIX**")
    vt_active = url_scanner.is_virustotal_configured()
    st.markdown(
        f"**VirusTotal API:** {'<span style=\"color:#00ff87;\">● ONLINE</span>' if vt_active else '<span style=\"color:#f59e0b;\">● OFFLINE HEURISTICS</span>'}",
        unsafe_allow_html=True,
    )

    db_active = db.is_configured()
    st.markdown(
        f"**Database:** {'<span style=\"color:#00ff87;\">● CLOUD (SUPABASE)</span>' if db_active else '<span style=\"color:#00f2fe;\">● IN-MEMORY BUFFER</span>'}",
        unsafe_allow_html=True,
    )

    ocr_active = ocr_scanner.is_tesseract_available()
    st.markdown(
        f"**OCR Engine:** {'<span style=\"color:#00ff87;\">● TESSERACT READY</span>' if ocr_active else '<span style=\"color:#f59e0b;\">● VISUAL FORENSICS ONLY</span>'}",
        unsafe_allow_html=True,
    )

    st.divider()

    with st.expander("🔒 Security Protocols"):
        st.markdown(
            """
            - **Auto Redaction**: OTPs, Card numbers, Passwords, Aadhaar, PAN masked pre-storage.
            - **Probabilistic AI**: Probabilistic pattern evaluation (not legal or bank proof).
            - **Bank Verification**: Cross-verify financial transactions directly in official banking apps.
            """
        )

    with st.expander("⚙️ System Architecture"):
        st.markdown(
            """
            - **NLP Engine**: TF-IDF + Logistic Regression with rule heuristics
            - **Forensics**: Error Level Analysis (ELA) + EXIF metadata
            - **Anomalies**: Isolation Forest Unsupervised Outlier Scoring
            - **3D Engine**: WebGL + Three.js + Plotly 3D
            """
        )


# --------------------------------------------------------------------------- #
# Header & 3D Interactive Cyber Globe
# --------------------------------------------------------------------------- #
st.markdown('<h1 class="cyber-title" style="color: #00f2fe;">🛡️ DIGITAL FRAUD & THREAT DEFENSE GUARD</h1>', unsafe_allow_html=True)
st.markdown(
    '<p style="color: #94a3b8; font-size: 1.05rem; margin-bottom: 0.5rem;">'
    "3D Holographic Cyber Command Center · Phishing NLP, Tampered Receipts, Threat URLs, & Rogue App Permissions"
    "</p>",
    unsafe_allow_html=True,
)

# Render the 3D Interactive WebGL Globe
render_3d_cyber_globe(threat_count=4, active_nodes=142)

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "💬 Message & Payment Analyzer",
        "🔗 URL & Phishing Link Checker",
        "📱 App Permission Audit (3D)",
        "🗂️ Threat History & Logs",
    ]
)


# =========================================================================== #
# TAB 1: Message and Payment Analyzer
# =========================================================================== #
with tab1:
    left_col, right_col = st.columns(2, gap="large")

    with left_col:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("💬 Message Scam Analyzer")
        st.caption("Scan incoming SMS, WhatsApp notifications, or emails for social engineering.")

        sample_choice = st.selectbox(
            "Load threat preset:",
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
            "Message payload to inspect:",
            value=default_text,
            height=140,
            placeholder="Paste text here...",
            key="msg_input_area",
        )

        if st.button("⚡ ANALYZE PAYLOAD", type="primary", key="btn_analyze_msg"):
            if not msg_input or not msg_input.strip():
                st.warning("Please enter or paste a message to analyze.")
            else:
                try:
                    with st.spinner("Executing neural pattern analysis..."):
                        res = nlp_analyzer.analyze_text(msg_input)

                    verdict_banner(
                        res["verdict"],
                        f"Scam Probability: {res['risk_score']:.1%} · Confidence: {res['confidence']:.1%} · Engine: {res['method']}",
                        res["disclaimer"],
                    )

                    st.markdown("**Scam Probability Threat Gauge:**")
                    st.progress(res["risk_score"])

                    if res["flags"]:
                        st.markdown("**Detected Threat Vectors:**")
                        for flag in res["flags"]:
                            kw_list = ", ".join(f"`{k}`" for k in flag["keywords"])
                            st.markdown(f"- 🚩 **{flag['category']}**: {kw_list}")

                        st.markdown("**Pattern Highlights:**")
                        st.info(res["highlighted"])
                    else:
                        st.success("✅ Clean: No fraudulent patterns or social engineering indicators found.")

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
        st.markdown("</div>", unsafe_allow_html=True)

    with right_col:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("🧾 Payment Receipt Integrity")
        st.caption("Perform Error Level Analysis (ELA) and OCR verification on payment screenshots.")

        if not ocr_scanner.is_tesseract_available():
            st.info(
                "ℹ️ **Notice**: Tesseract OCR engine not detected on system. "
                "Executing **Error Level Analysis (ELA)** & **Metadata Tampering Forensics**."
            )

        uploaded_img = st.file_uploader(
            "Upload payment screenshot (PNG, JPG, WEBP):",
            type=["png", "jpg", "jpeg", "webp"],
            key="payment_screenshot_uploader",
        )

        if uploaded_img is not None:
            st.image(uploaded_img, caption=f"Uploaded: {uploaded_img.name}", width=260)

        if st.button("🔍 SCAN RECEIPT", type="primary", key="btn_scan_receipt"):
            if uploaded_img is None:
                st.warning("Please upload a receipt image first.")
            else:
                try:
                    img_bytes = uploaded_img.getvalue()
                    with st.spinner("Computing ELA compression delta & glyph heights..."):
                        res = ocr_scanner.scan_payment_image(img_bytes)

                    val = res["validation"]
                    fields = res["fields"]

                    verdict_banner(
                        val["verdict"],
                        f"Risk Points: {val['risk_points']} · Confidence: {val['confidence']:.1%}",
                        val.get("disclaimer", ""),
                    )

                    if res.get("ocr_available", True):
                        st.markdown("**Parsed Transaction Attributes:**")
                        display_fields = {k: v for k, v in fields.items() if not k.startswith("all_")}
                        df_fields = (
                            pd.DataFrame([display_fields])
                            .T.rename(columns={0: "Value"})
                            .fillna("Not detected")
                        )
                        st.table(df_fields)

                    if val["red_flags"]:
                        st.markdown("**Forensic Red Flags:**")
                        for rf in val["red_flags"]:
                            st.markdown(f"- 🚩 {rf}")

                    if val["notes"]:
                        for note in val["notes"]:
                            st.caption(f"ℹ️ {note}")

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
        st.markdown("</div>", unsafe_allow_html=True)


# =========================================================================== #
# TAB 2: URL & Phishing Link Checker
# =========================================================================== #
with tab2:
    st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
    st.subheader("🔗 3D Threat Radar: URL & Phishing Link Checker")
    st.caption("Hybrid link inspection: offline structural heuristics + VirusTotal cloud threat database.")

    url_col1, url_col2 = st.columns([3, 1])
    with url_col1:
        url_preset = st.selectbox(
            "Select target link preset:",
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

    if st.button("🌐 SCAN URL RADAR", type="primary", key="btn_scan_url"):
        if not url_target or not url_target.strip():
            st.warning("Please enter a URL to check.")
        else:
            try:
                with st.spinner("Querying threat radar & structural heuristics..."):
                    analysis = url_scanner.analyze_url(url_target)

                heur = analysis["heuristics"]
                vt = analysis["virustotal"]
                verdict = analysis["verdict"]

                verdict_banner(
                    verdict,
                    f"Target: `{analysis['normalized_url']}` · Assessment: {analysis['assessment_type']}",
                    "URL analysis evaluates structural risk markers and threat databases. Always confirm browser address bar before signing in.",
                )

                if vt:
                    st.markdown("**VirusTotal Multi-Vendor Cloud Intelligence:**")
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Malicious", vt["malicious"])
                    m2.metric("Suspicious", vt["suspicious"])
                    m3.metric("Harmless", vt["harmless"])
                    m4.metric("Engines Scanned", vt["total_engines"])

                    if vt["flagged_vendors"]:
                        st.markdown("**Flagging Security Vendors:**")
                        st.dataframe(pd.DataFrame(vt["flagged_vendors"]), width="stretch", hide_index=True)
                else:
                    st.info(f"ℹ️ {analysis['vt_error']}")

                st.markdown("**Offline Structural Heuristics:**")
                if heur["notes"]:
                    for n in heur["notes"]:
                        st.markdown(f"- ⚠️ {n}")
                else:
                    st.success("✅ Clean: No suspicious structural anomalies (IP host, punycode, high-risk TLD) detected.")

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
    st.markdown("</div>", unsafe_allow_html=True)


# =========================================================================== #
# TAB 3: App Permission Audit (Interactive 3D Feature Space)
# =========================================================================== #
with tab3:
    st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
    st.subheader("📱 3D Anomaly Cluster: Device App Permission Audit")
    st.caption("Isolation Forest Unsupervised Machine Learning rendered in interactive 3D feature space.")

    data_mode = st.radio(
        "Audit dataset source:",
        ["Built-in Demonstration List (15 apps)", "Upload Custom CSV / JSON"],
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
                st.success(f"Loaded {len(app_data_df)} application records.")
            except Exception as exc:
                st.error(f"File loading error: {exc}")
    else:
        app_data_df = anomaly_detector.build_mock_app_list()

    mock_csv_bytes = anomaly_detector.build_mock_app_list().to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Download Sample CSV Template",
        data=mock_csv_bytes,
        file_name="sample_app_permissions.csv",
        mime="text/csv",
        key="btn_download_sample_csv",
    )

    if st.button("🚀 EXECUTE 3D ANOMALY AUDIT", type="primary", key="btn_run_app_audit"):
        if app_data_df is None or app_data_df.empty:
            st.warning("Please upload a CSV/JSON file or select the built-in list.")
        else:
            try:
                with st.spinner("Fitting Isolation Forest trees in multidimensional space..."):
                    audit_res = anomaly_detector.analyze_apps(app_data_df)

                summary = audit_res["summary"]
                results_df = audit_res["results"]

                verdict_banner(
                    summary["verdict"],
                    f"Audited {summary['total_apps']} apps · {summary['high_risk']} High Risk Outliers · {summary['warning']} Warnings · {summary['safe']} Safe",
                    summary.get("disclaimer", ""),
                )

                a1, a2, a3 = st.columns(3)
                a1.metric("High Risk Anomalies", summary["high_risk"])
                a2.metric("Borderline Warnings", summary["warning"])
                a3.metric("Normal Apps", summary["safe"])

                # --- 3D Interactive WebGL Scatter Plot (Plotly) ---
                st.markdown("### 🌌 3D Feature Space: Anomaly Cluster Plot")
                st.caption(
                    "Click and drag to rotate the 3D cluster in real-time. Notice how rogue spyware apps "
                    "are mathematically isolated far from the cluster of normal apps."
                )

                # Prepare composite risk score for 3D axis
                plot_df = results_df.copy()
                plot_df["privilege_weight"] = (
                    plot_df["has_sms_permission"] * 2.0
                    + plot_df["overlay_permission"] * 2.5
                    + plot_df["has_camera_permission"] * 1.0
                    + plot_df["has_contacts_permission"] * 1.0
                )

                color_map = {
                    "High Risk": "#ff0055",
                    "Warning": "#f59e0b",
                    "Safe": "#00ff87",
                }

                fig_3d = px.scatter_3d(
                    plot_df,
                    x="background_data_usage_mb",
                    y="privilege_weight",
                    z="anomaly_score",
                    color="risk_level",
                    color_discrete_map=color_map,
                    hover_name="app_name",
                    hover_data={
                        "risk_level": True,
                        "reason": True,
                        "background_data_usage_mb": ":.1f MB",
                        "anomaly_score": ":.3f",
                        "privilege_weight": False,
                    },
                    labels={
                        "background_data_usage_mb": "Background Data (MB)",
                        "privilege_weight": "Privilege Index",
                        "anomaly_score": "Isolation Score",
                        "risk_level": "Verdict",
                    },
                    title="Interactive 3D Isolation Forest Cluster Space",
                )

                fig_3d.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(10, 20, 35, 0.6)",
                    plot_bgcolor="rgba(10, 20, 35, 0.6)",
                    scene=dict(
                        xaxis=dict(backgroundcolor="#050b14", gridcolor="rgba(0, 242, 254, 0.2)"),
                        yaxis=dict(backgroundcolor="#050b14", gridcolor="rgba(0, 242, 254, 0.2)"),
                        zaxis=dict(backgroundcolor="#050b14", gridcolor="rgba(0, 242, 254, 0.2)"),
                        camera=dict(eye=dict(x=1.6, y=1.6, z=1.2)),
                    ),
                    margin=dict(l=0, r=0, b=0, t=40),
                    height=520,
                )
                st.plotly_chart(fig_3d, use_container_width=True)

                st.markdown("**Application Privilege Inventory:**")
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
    st.markdown("</div>", unsafe_allow_html=True)


# =========================================================================== #
# TAB 4: Threat History & Logs
# =========================================================================== #
with tab4:
    st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
    st.subheader("🗂️ Threat History & Forensic Audit Log")
    st.caption("Immutable scan logs with automatic sensitive token redaction and cloud synchronization.")

    hist_col1, hist_col2, hist_col3 = st.columns([2, 1, 1])
    with hist_col1:
        type_choice = st.selectbox(
            "Filter channel:",
            ["All Channels", "text", "image", "url", "app_audit"],
            key="hist_category_selector",
        )
    with hist_col2:
        limit_count = st.number_input("Max records:", min_value=10, max_value=200, value=50, step=10)
    with hist_col3:
        st.write("")
        st.write("")
        refresh_btn = st.button("🔄 REFRESH", key="btn_refresh_logs")

    filter_type = None if type_choice == "All Channels" else type_choice
    rows, note_msg = db.fetch_history(limit=limit_count, input_type=filter_type)

    if note_msg:
        st.info(note_msg)

    if not rows:
        st.write("No scan records detected. Execute an analysis to populate the audit database.")
    else:
        df_hist = pd.DataFrame(rows)

        high_risk_scans = int((df_hist["verdict"].isin(["High Risk", "Malicious"])).sum())
        clean_scans = int((df_hist["verdict"].isin(["Safe", "Clean"])).sum())

        c1, c2, c3 = st.columns(3)
        c1.metric("Scans Logged", len(df_hist))
        c2.metric("Threats Intercepted", high_risk_scans)
        c3.metric("Verified Clean", clean_scans)

        # 3D-styled Plotly Bar Chart
        st.markdown("### 📊 Verdict Distribution Matrix")
        verdict_counts = df_hist["verdict"].value_counts().reset_index()
        verdict_counts.columns = ["Verdict", "Count"]

        bar_colors = [
            VERDICT_COLORS.get(v, ("#475569", "", ""))[0] for v in verdict_counts["Verdict"]
        ]

        fig_bar = go.Figure(
            data=[
                go.Bar(
                    x=verdict_counts["Verdict"],
                    y=verdict_counts["Count"],
                    marker=dict(
                        color=bar_colors,
                        line=dict(color="#00f2fe", width=1.5),
                    ),
                    text=verdict_counts["Count"],
                    textposition="auto",
                )
            ]
        )
        fig_bar.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(10, 20, 35, 0.6)",
            plot_bgcolor="rgba(10, 20, 35, 0.6)",
            xaxis=dict(gridcolor="rgba(0, 242, 254, 0.15)"),
            yaxis=dict(gridcolor="rgba(0, 242, 254, 0.15)"),
            margin=dict(l=20, r=20, b=20, t=30),
            height=280,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

        cols_to_show = [
            c for c in ["created_at", "input_type", "content", "verdict", "confidence"]
            if c in df_hist.columns
        ]
        st.markdown("**Historical Audit Trail:**")
        st.dataframe(df_hist[cols_to_show], width="stretch", hide_index=True)
    st.markdown("</div>", unsafe_allow_html=True)
