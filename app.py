
from datetime import datetime

import streamlit as st

from src.detector import analyze_url


# ---------- Page configuration ----------
st.set_page_config(
    page_title="PhishGuard | Security Center",
    page_icon="🛡️",
    layout="wide",
)


# ---------- Session state ----------
if "history" not in st.session_state:
    st.session_state.history = []


# ---------- Custom styling ----------
st.markdown(
    """
    <style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
    }
    .hero {
        padding: 1.5rem;
        border: 1px solid #354052;
        border-radius: 16px;
        margin-bottom: 1.5rem;
    }
    .muted {
        color: #9CA3AF;
        font-size: 0.9rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------- Sidebar ----------
with st.sidebar:
    st.title("🛡️ PhishGuard")
    st.caption("URL Security Analysis")

    st.divider()

    st.subheader("About")
    st.write(
        "PhishGuard identifies common URL characteristics "
        "associated with phishing attempts."
    )

    st.subheader("Detection rules")
    st.markdown(
        """
        - HTTP instead of HTTPS
        - IP addresses used as hosts
        - Embedded URL credentials
        - Suspicious keywords
        - Known URL shorteners
        - Unusually long URLs
        - Excessive hostname labels
        """
    )

    st.divider()

    st.caption(
        "Educational defensive tool. Results are heuristic, "
        "not a guarantee of website safety."
    )


# ---------- Header ----------
st.markdown(
    """
    <div class="hero">
        <h1>PhishGuard Security Center</h1>
        <p>
            Analyze suspicious URLs with explainable,
            rule-based security checks.
        </p>
        <p class="muted">
            Local analysis • No intentional URL visits •
            Transparent findings
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------- URL analysis ----------
st.subheader("🔎 URL Analyzer")

with st.form("url_analysis_form"):
    url = st.text_input(
        "URL to analyze",
        placeholder="https://example.com",
        help="Enter a URL as text. Do not open suspicious links.",
    )

    submitted = st.form_submit_button(
        "Analyze URL",
        type="primary",
        use_container_width=True,
    )


if submitted:
    if not url.strip():
        st.warning("Enter a URL before starting the analysis.")
    else:
        result = analyze_url(url)

        record = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "url": result["url"],
            "risk": result["risk"],
            "score": result["score"],
            "findings": result["findings"],
        }

        st.session_state.history.insert(0, record)
        st.session_state.history = st.session_state.history[:50]

        st.session_state.latest_result = record


# ---------- Latest result ----------
if "latest_result" in st.session_state:
    result = st.session_state.latest_result

    st.divider()
    st.subheader("📊 Latest Analysis")

    st.code(result["url"], language=None)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Risk Score", f"{result['score']}/100")

    with col2:
        st.metric("Risk Classification", result["risk"])

    with col3:
        st.metric("Indicators Found", len(result["findings"]))

    if result["risk"] == "HIGH":
        st.error("High risk indicators detected.")
    elif result["risk"] == "MEDIUM":
        st.warning("Some suspicious indicators were detected.")
    elif result["risk"] == "LOW":
        st.success(
            "Few configured warning indicators were detected. "
            "This does not establish that the URL is safe."
        )
    elif result["risk"] == "INVALID":
        st.error("The URL did not pass validation.")
    else:
        st.info("No URL was provided.")

    st.markdown("#### Detection findings")

    for finding in result["findings"]:
        st.markdown(f"- {finding}")

    with st.expander("View technical JSON output"):
        st.json(result)


# ---------- Analysis history ----------
st.divider()
st.subheader("🕘 Recent Analysis History")

st.caption(
    "The most recent 50 analyses are kept in this browser session. "
    "They are not saved permanently."
)

if st.session_state.history:
    history_rows = [
        {
            "Time": item["time"],
            "URL": item["url"],
            "Risk": item["risk"],
            "Score": item["score"],
        }
        for item in st.session_state.history
    ]

    st.dataframe(
        history_rows,
        use_container_width=True,
        hide_index=True,
    )

    if st.button("Clear session history"):
        st.session_state.history = []
        st.session_state.pop("latest_result", None)
        st.rerun()
else:
    st.info("No analyses yet. Submit a URL above to get started.")


# ---------- Footer ----------
st.divider()

st.caption(
    "PhishGuard | Educational cybersecurity project | "
    "Rule-based detection is not a substitute for independent verification."
)
