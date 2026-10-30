# 🛡️ PhishGuard
### Explainable Phishing URL Risk Analyzer

PhishGuard is a Python-based cybersecurity project that analyzes URLs for common phishing indicators using transparent, rule-based detection. It provides a command-line interface (CLI) and an interactive web dashboard built with Streamlit.

The goal is to demonstrate practical skills in Python development, defensive security, input validation, automated testing, and security-tool design.

> **Disclaimer:** PhishGuard is an educational project. Its heuristic risk score is not a probability of phishing and cannot guarantee that a URL is safe or malicious.

## ✨ Features

- **URL analysis:** Examine URL text without intentionally visiting the destination.
- **Explainable detection:** Display the indicators that contributed to a result.
- **Heuristic risk scoring:** Calculate a score from 0 to 100.
- **URL validation:** Reject malformed inputs and unsupported URL schemes.
- **Command-line interface:** Analyze URLs directly from a terminal.
- **Interactive dashboard:** View results through a Streamlit web interface.
- **Analysis history:** Review recent analyses during the current dashboard session.
- **Automated tests:** Verify core detection and validation behavior.
- **JSON output:** Display structured analysis results.

## 🔍 Detection Indicators

PhishGuard checks for characteristics such as:

- HTTP instead of HTTPS.
- IP addresses used as hostnames.
- Embedded credentials in URLs.
- Suspicious keywords in hostnames or URL paths.
- Known URL-shortening domains.
- Unusually long URLs.
- An unusually high number of hostname labels.

These characteristics can occur in legitimate URLs as well. Findings must be interpreted in context.

## 🧰 Technology Stack

- **Language:** Python
- **Web interface:** Streamlit
- **Testing:** Python `unittest`
- **Version control:** Git and GitHub
- **Standard libraries:** `urllib.parse`, `ipaddress`, `argparse`, `json`, `re`

## 📁 Project Structure

```text
PhishGuard/
├── src/
│   ├── __init__.py
│   └── detector.py
├── tests/
│   └── test_detector.py
├── app.py
├── main.py
├── requirements.txt
├── .gitignore
└── README.md
```

## ⚙️ Installation

### Prerequisites

- Python 3.10 or newer.
- Git (optional for local use, required for the Git workflow below).
- VS Code or another Python editor.


**Khouloud BM**

Computer Science Student | Cybersecurity & Networking

GitHub: (https://github.com/khouloudbm10)


