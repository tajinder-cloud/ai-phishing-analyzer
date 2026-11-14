import streamlit as st
import re
from datetime import datetime

st.set_page_config(page_title="CyberGuard AI | Tajinder Kumar", page_icon="⚡", layout="centered")

# Top Header
st.title("⚡ CYBERGUARD AI : CLOUD THREAT ENGINE")
st.caption("Intelligent Phishing, Malicious URL & Social Engineering Detection System")

# Student Details Box
st.info("👨‍💻 **Developed By:** Tajinder Kumar (Roll No: 25801100)  |  🏛️ **University:** Sant Baba Bhag Singh University — B.Tech CSE (AI/ML)")

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

    found_words = [w for w in URGENCY_WORDS if w in full_text]
    if found_words:
        ai_score = min(len(found_words) * 15, 45)
        alerts.append(f"**[AI NLP Engine]** Detected manipulation keywords: {', '.join(found_words)}")

    links = re.findall(r'(https?://[^\s]+)', content)
    if links:
        for link in links:
            if "http://" in link:
                url_score += 20
                alerts.append(f"**[SSL/TLS Check]** Unencrypted HTTP link: {link}")
            if any(link.lower().endswith(t) or f"{t}/" in link.lower() for t in RISKY_TLDS):
                url_score += 25
                alerts.append(f"**[Domain Check]** High-risk domain extension: {link}")
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', link):
                url_score += 30
                alerts.append(f"**[IP Check]** Raw IP address used instead of domain: {link}")
    url_score = min(url_score, 40)

    if sender:
        if "@" not in sender:
            sender_score = 15
            alerts.append("**[Header Check]** Missing '@' symbol in sender address.")
        else:
            domain_part = sender.split("@")[-1].lower()
            if any(c.isdigit() for c in domain_part.split(".")[0]):
                sender_score = 15
                alerts.append(f"**[Spoofing Check]** Sender domain '{domain_part}' contains suspicious numbers.")

    total_risk = min(ai_score + url_score + sender_score, 100)
    return total_risk, ai_score, url_score, len(links), alerts

tab1, tab2, tab3 = st.tabs(["🚀 Threat Scanner", "📊 AI Architecture", "🎓 Project Profile"])

with tab1:
    sample_mode = st.selectbox(
        "⚡ Quick Load Test Sample (For Viva Demo):",
        ["-- Type Custom Input --", "🚨 Sample 1: Bank KYC Phishing Attack", "✅ Sample 2: Safe Official University Email"]
    )

    if sample_mode == "🚨 Sample 1: Bank KYC Phishing Attack":
        d_sender = "alert@sbi-kyc-update99.xyz"
        d_subject = "URGENT: Your bank account is suspended! Verify immediately"
        d_body = "Dear user, unauthorized login attempt detected. Click below within 24 hours to update KYC or your account will remain blocked: http://192.168.10.45/login"
    elif sample_mode == "✅ Sample 2: Safe Official University Email":
        d_sender = "info@sbbsuniversity.ac.in"
        d_subject = "Industrial Training Viva Schedule for B.Tech CSE"
        d_body = "Dear students, please bring your hardcopy training report and laptop for the project presentation tomorrow at 10:00 AM. Visit https://www.sbbsuniversity.ac.in for guidelines."
    else:
        d_sender, d_subject, d_body = "", "", ""

    sender_in = st.text_input("📧 Sender Email Address", value=d_sender)
    subject_in = st.text_input("📝 Subject Line", value=d_subject)
    body_in = st.text_area("📄 Email Content / Server Log", value=d_body, height=120)

    if st.button("⚡ EXECUTE AI CLOUD SCAN", use_container_width=True, type="primary"):
        if not subject_in and not body_in:
            st.warning("⚠️ Please enter text or select a test sample above.")
        else:
            total, ai_s, url_s, link_count, findings = scan_payload(sender_in, subject_in, body_in)

            st.divider()
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
                st.success("✅ **CLEAN PAYLOAD (SAFE)** — No malicious indicators detected.")

            st.write("🔎 **Security Engine Logs:**")
            if findings:
                for item in findings:
                    st.write("- " + item)
            else:
                st.write("- **[All Modules]** Passed security verification checks.")

            st.caption(f"Cloud Scan ID: CG-{datetime.now().strftime('%H%M%S')} | Executed by Tajinder Kumar (25801100)")

with tab2:
    st.subheader("🧠 How the 4 Training Domains Work Together")
    st.write("1. **Python Core:** Handles regular expression (`re`) parsing, string tokenization, and UI rendering.")
    st.write("2. **Artificial Intelligence (NLP Heuristics):** Evaluates psychological urgency and social engineering intent.")
    st.write("3. **Cyber Security Module:** Inspects URLs for missing SSL (`http://`), raw IP obfuscation, and risky domains.")
    st.write("4. **Cloud Computing:** Deployed as a serverless SaaS web application on Streamlit Community Cloud.")

with tab3:
    st.subheader("🎓 Industrial Training Project Record")
    st.write("- **Project Title:** CyberGuard AI: Cloud-Based Phishing & Threat Analyzer")
    st.write("- **Training Domains:** Python + Cloud Computing + Cyber Security and AI")
    st.write("- **Student Name:** Tajinder Kumar")
    st.write("- **University Roll No.:** 25801100")
    st.write("- **Department:** B.Tech CSE (AI/ML)")
    st.write("- **Institution:** Sant Baba Bhag Singh University, Jalandhar (Punjab)")
