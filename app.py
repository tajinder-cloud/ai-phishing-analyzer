import streamlit as st
import re
from datetime import datetime

# Page Configuration
st.set_page_config(page_title="AI Cyber Threat & Phishing Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ AI-Powered Email & Log Threat Analyzer")
st.write("**Project Domain:** Python | Cloud Computing | Cyber Security | AI")
st.markdown("---")

# AI / Heuristic Threat Keywords Database
URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspended", "verify your account", "blocked",
    "unauthorized", "click below", "update payment", "24 hours", "security alert",
    "expire", "password reset", "bank account", "kyc", "lottery", "winner"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".info", ".tk", ".ml", ".ga", ".cf", ".pw"]

def analyze_content(sender, subject, body):
    score = 0
    findings = []
    
    combined_text = f"{subject} {body}".lower()
    
    # 1. AI Keyword & NLP Intent Analysis
    matched_keywords = [word for word in URGENCY_KEYWORDS if word in combined_text]
    if matched_keywords:
        score += len(matched_keywords) * 15
        findings.append(f"⚠️ **AI Intent Analysis:** Detected {len(matched_keywords)} social engineering/urgency trigger(s): `{', '.join(matched_keywords)}`")
    
    # 2. Cyber Security URL Extraction & Inspection
    urls = re.findall(r'(https?://[^\s]+)', body)
    if urls:
        findings.append(f"🔗 **Extracted Links ({len(urls)}):** " + ", ".join(urls))
        for url in urls:
            if "http://" in url:
                score += 20
                findings.append(f"❌ **Unencrypted Link:** `{url}` uses insecure HTTP instead of HTTPS.")
            if any(url.lower().endswith(tld) or f"{tld}/" in url.lower() for tld in SUSPICIOUS_TLDS):
                score += 25
                findings.append(f"🚨 **High-Risk Domain Extension:** `{url}` uses a TLD commonly associated with phishing.")
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                score += 30
                findings.append(f"🚨 **IP-Based URL Detected:** `{url}` hides the domain name using a raw IP address.")

    # 3. Sender Email Spoofing Check
    if sender:
        if "@" not in sender:
            score += 20
            findings.append("❌ **Invalid Sender Address:** Missing '@' symbol.")
        else:
            domain = sender.split("@")[-1].lower()
            if any(char.isdigit() for char in domain.split(".")[0]):
                score += 15
                findings.append(f"⚠️ **Suspicious Sender Domain:** `{domain}` contains numbers often used in lookalike/spoofed domains.")

    # Cap score at 100
    score = min(score, 100)
    return score, findings

# Sidebar Details for Teacher/Viva
with st.sidebar:
    st.header("📋 Project Information")
    st.write("**Course:** B.Tech CSE (AI/ML)")
    st.write("**Tech Stack:** Python, Regex, NLP Heuristics, Streamlit Cloud")
    st.markdown("---")
    st.subheader("How It Works")
    st.write("1. **Input:** Paste suspicious email details or server message logs.")
    st.write("2. **AI Engine:** Scans text for social engineering and urgency patterns.")
    st.write("3. **Cyber Check:** Inspects embedded URLs, protocols, and sender domains.")
    st.write("4. **Cloud Output:** Generates a real-time threat score and security report.")

# Main Input Form
col1, col2 = st.columns([1.2, 1])

with col1:
    st.subheader("📩 Enter Email / Message Details")
    sender_input = st.text_input("Sender Email Address", placeholder="e.g., support@secure-login123.xyz")
    subject_input = st.text_input("Email Subject", placeholder="e.g., URGENT: Your account will be suspended in 24 hours")
    body_input = st.text_area("Message Body / Log Content", height=180, placeholder="Paste the email text or log here... Example: Dear user, unauthorized login detected. Click below to verify your account immediately: http://192.168.1.55/login")
    
    analyze_btn = st.button("🔍 Run AI Security Scan", use_container_width=True)

with col2:
    st.subheader("📊 Threat Assessment Report")
    if analyze_btn:
        if not subject_input and not body_input:
            st.warning("Please enter a subject or message body to analyze.")
        else:
            risk_score, report_items = analyze_content(sender_input, subject_input, body_input)
            
            st.metric(label="Calculated Threat Risk Score", value=f"{risk_score} / 100")
            st.progress(risk_score / 100)
            
            if risk_score >= 60:
                st.error("🚨 **STATUS: HIGH-RISK PHISHING DETECTED** — Do not click any links or reply.")
            elif risk_score >= 25:
                st.warning("⚠️ **STATUS: SUSPICIOUS CONTENT** — Proceed with caution and verify the sender manually.")
            else:
                st.success("✅ **STATUS: SAFE / LOW RISK** — No obvious phishing indicators found.")
            
            st.markdown("**Detailed Security Findings:**")
            if report_items:
                for item in report_items:
                    st.write(item)
            else:
                st.write("✔️ Clean text, encrypted links, and standard sender format.")
            
            st.caption(f"Scan completed on Cloud Server at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        st.info("Fill in the details on the left and click **Run AI Security Scan** to generate the report.")
