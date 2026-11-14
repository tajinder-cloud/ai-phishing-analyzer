import streamlit as st
import re
from datetime import datetime

# Page Setup
st.set_page_config(
    page_title="CyberGuard AI | Tajinder Kumar",
    page_icon="⚡",
    layout="centered"
)

# Custom Dark Cyber Theme CSS
st.markdown("""
    <style>
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .header-box {
        background: linear-gradient(90deg, #1e293b 0%, #0f172a 100%);
        border-left: 5px solid #00f2fe;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        box-shadow: 0 4px 15px rgba(0, 242, 254, 0.15);
    }
    .student-badge {
        background-color: #1e293b;
        border: 1px solid #334155;
        padding: 12px 18px;
        border-radius: 8px;
        margin-bottom: 25px;
        display: flex;
        justify-content: space-between;
        flex-wrap: wrap;
    }
    div[data-testid="stMetricValue"] {
        color: #00f2fe !important;
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

# Top Title Banner
st.markdown("""
    <div class="header-box">
        <h2 style="margin:0; color:#00f2fe;">⚡ CYBERGUARD AI : CLOUD THREAT ENGINE</h2>
        <p style="margin:5px 0 0 0; color:#94a3b8;">Intelligent Phishing, Malicious URL & Social Engineering Detection System</p>
    </div>
""", unsafe_allow_html=True)

# Student & University Details Banner
st.markdown("""
    <div class="student-badge">
        <div><b>👨‍💻 Developed By:</b> Tajinder Kumar (Roll No: 25801100)</div>
        <div><b>🎓 Submitted To:</b> Dr. Jagdeep Kaur (HOD)</div>
        <div><b>🏛️ University:</b> Sant Baba Bhag Singh University — B.Tech CSE (AI/ML)</div>
    </div>
""", unsafe_allow_html=True)

# Threat Databases
URGENCY_WORDS = [
    "urgent", "immediately", "suspended", "verify", "blocked", "unauthorized",
    "click below", "update payment", "24 hours", "security alert", "expire",
    "password reset", "bank", "kyc", "lottery", "winner", "free", "prize"
]
RISKY_TLDS = [".xyz", ".top", ".club", ".info", ".tk", ".ml", ".ga", ".cf", ".pw"]

def scan_payload(sender, subject, content):
    ai_score = 0
    url_score = 0
    sender_score = 0
    alerts = []

    full_text = f"{subject} {content}".lower()

    # 1. AI NLP Trigger Check
    found_words = [w for w in URGENCY_WORDS if w in full_text]
    if found_words:
        ai_score = min(len(found_words) * 15, 45)
        alerts.append(("AI NLP Engine", f"Detected high-pressure manipulation keywords: {', '.join(found_words)}"))

    # 2. Cyber URL Check
    links = re.findall(r'(https?://[^\s]+)', content)
    if links:
        for link in links:
            if "http://" in link:
                url_score += 20
                alerts.append(("SSL/TLS Check", f"Unencrypted HTTP protocol found in link: {link}"))
            if any(link.lower().endswith(t) or f"{t}/" in link.lower() for t in RISKY_TLDS):
                url_score += 25
                alerts.append(("Domain Threat Check", f"High-risk top-level domain detected: {link}"))
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', link):
                url_score += 30
                alerts.append(("IP Obfuscation Check", f"Raw IP address used instead of domain name: {link}"))
    url_score = min(url_score, 40)

    # 3. Sender Authentication Check
    if sender:
        if "@" not in sender:
            sender_score = 15
            alerts.append(("Header Check", "Malformed sender email address (missing '@' symbol)."))
        else:
            domain_part = sender.split("@")[-1].lower()
            if any(c.isdigit() for c in domain_part.split(".")[0]):
                sender_score = 15
                alerts.append(("Spoofing Check", f"Sender domain '{domain_part}' contains suspicious numeric patterns."))

    total_risk = min(ai_score + url_score + sender_score, 100)
    return total_risk, ai_score, url_score, sender_score, len(links), alerts

# Navigation Tabs (New Structure)
tab1, tab2, tab3 = st.tabs(["🚀 Threat Scanner", "📊 Detailed AI Breakdown", "🎓 Project Profile"])

with tab1:
    st.markdown("#### 🔍 Input Email or Log Payload for Cloud Inspection")
    
    # Quick Demo Selector for Viva
    sample_mode = st.selectbox(
        "⚡ Quick Load Test Sample (Helpful for Viva Demo):",
        ["-- Type Custom Input --", "🚨 Sample 1: Bank KYC Phishing Attack", "✅ Sample 2: Safe Official University Email"]
    )

    if sample_mode == "🚨 Sample 1: Bank KYC Phishing Attack":
        default_sender = "alert@sbi-kyc-update99.xyz"
        default_subject = "URGENT: Your bank account is suspended! Verify immediately"
        default_body = "Dear user, unauthorized login attempt detected. Click below within 24 hours to update KYC or your account will remain blocked: http://192.168.10.45/login"
    elif sample_mode == "✅ Sample 2: Safe Official University Email":
        default_sender = "hod.cse@sbbsuniversity.ac.in"
        default_subject = "Industrial Training Viva Schedule for B.Tech CSE"
        default_body = "Dear students, please bring your hardcopy training report and laptop for the project presentation tomorrow at 10:00 AM. Visit https://www.sbbsuniversity.ac.in for guidelines."
    else:
        default_sender = ""
        default_subject = ""
        default_body = ""

    sender_in = st.text_input("📧 Sender Email Address", value=default_sender, placeholder="e.g., service@paytm-verify12.xyz")
    subject_in = st.text_input("📝 Subject Line", value=default_subject, placeholder="e.g., Urgent Security Alert")
    body_in = st.text_area("📄 Email Content / Server Log", value=default_body, height=130, placeholder="Paste full message or log payload here...")

    run_scan = st.button("⚡ EXECUTE AI CLOUD SCAN", use_container_width=True, type="primary")

    if run_scan:
        if not subject_in and not body_in:
            st.warning("⚠️ Please enter text or select a test sample above to run the scan.")
        else:
            total, ai_s, url_s, send_s, link_count, findings = scan_payload(sender_in, subject_in, body_in)

            st.markdown("---")
            st.markdown("#### 📈 Real-Time Cloud Telemetry")

            # 4-Card Horizontal Metric Structure
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Overall Threat", f"{total}%")
            m2.metric("AI NLP Risk", f"{ai_s}/45")
            m3.metric("URL Risk", f"{url_s}/40")
            m4.metric("Links Found", f"{link_count}")

            st.progress(total / 100)

            if total >= 60:
                st.error("🚨 **CRITICAL THREAT DETECTED (HIGH-RISK PHISHING)** — Quarantine message immediately.")
            elif total >= 25:
                st.warning("⚠️ **MODERATE RISK (SUSPICIOUS)** — Verify sender identity before interacting.")
            else:
                st.success("✅ **CLEAN PAYLOAD (SAFE)** — No malicious indicators or phishing triggers detected.")

            st.markdown("##### 🔎 Security Engine Logs:")
            if findings:
                for module, msg in findings:
                    st.markdown(f"- **[{module}]** {msg}")
            else:
                st.markdown("- **[All Modules]** Passed security verification checks.")

            st.caption(f"Cloud Scan ID: CG-{datetime.now().strftime('%H%M%S')} | Executed by Tajinder Kumar (25801100)")

with tab2:
    st.subheader("🧠 How the 4 Training Domains Work Together")
    st.info("This architecture combines Python, Cloud Computing, Cyber Security, and AI into a unified pipeline.")
    st.markdown("""
    1. **Python Core:** Handles regular expression (`re`) parsing, string tokenization, and UI rendering.
    2. **Artificial Intelligence (NLP Heuristics):** Evaluates psychological urgency, fear-inducing keywords, and social engineering intent.
    3. **Cyber Security Module:** Inspects URLs for missing SSL (`http://`), raw IP obfuscation, and high-risk domains (`.xyz`, `.top`).
    4. **Cloud Computing:** Deployed as a serverless SaaS web application on Streamlit Community Cloud.
    """)

with tab3:
    st.subheader("🎓 Industrial Training Project Record")
    st.table({
        "Attribute": [
            "Project Title",
            "Training Domains",
            "Student Name",
            "University Roll No.",
            "Department",
            "Submitted To",
            "Institution"
        ],
        "Details": [
            "CyberGuard AI: Cloud-Based Phishing & Threat Analyzer",
            "Python + Cloud Computing + Cyber Security and AI",
            "Tajinder Kumar",
            "25801100",
            "B.Tech CSE (AI/ML)",
            "Dr. Jagdeep Kaur (HOD)",
            "Sant Baba Bhag Singh University, Jalandhar (Punjab)"
        ]
    })
