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

### 1. Clone the repository

Replace the example URL with your actual GitHub repository URL.

```bash
git clone https://github.com/khouloudbm10/PhishGuard.git
cd PhishGuard
```

Alternatively, download the repository as a ZIP file and extract it.

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can use the virtual environment's Python executable directly instead.

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the web dashboard

```bash
python -m streamlit run app.py
```

Open the local address printed in the terminal.

## 🚀 Usage

### Command-line interface

Analyze a sample URL:

```bash
python main.py https://example.com
```

Analyze a reserved documentation IP address without visiting it:

```bash
python main.py http://192.0.2.1/login
```

The CLI displays the risk classification, score, findings, and JSON output.

### Web dashboard

Launch the dashboard:

```bash
python -m streamlit run app.py
```

Enter a URL as text and select **Analyze URL**. The application displays the analysis, individual findings, and technical JSON output.

## 🧪 Run the Tests

From the project root:

```bash
python -m unittest discover -s tests -v
```

The tests cover URL validation, detection indicators, and result structure. The expected number of tests may change as the project evolves.

## 📊 Risk Scoring

PhishGuard combines configured rule-based scores and caps the total at 100.

| Score | Classification |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–100 | HIGH |

Invalid and empty inputs receive separate classifications.

These thresholds are manually configured heuristics, not statistically validated predictions. A low score does not establish that a website is trustworthy.

## 🔐 Security and Limitations

- PhishGuard does not intentionally open or visit submitted URLs.
- It does not currently use a live threat-intelligence feed or a trained machine-learning model.
- It does not verify website ownership, reputation, or actual page content.
- HTTPS alone does not establish legitimacy.
- Legitimate URLs may trigger warnings, and malicious URLs may evade detection.
- URL parsing and local validation do not replace comprehensive security analysis.
- Analysis history is held in the dashboard session and is not a permanent database.

Use reserved example domains and documentation IP addresses when testing. Do not visit suspicious links to validate a result.

## 🛣️ Future Improvements

- Expand automated tests with additional edge cases.
- Add carefully evaluated public phishing datasets for offline benchmarking.
- Measure precision, recall, and false-positive rates against labeled test data.
- Add domain normalization and internationalized-domain test cases.
- Introduce configurable detection rules.
- Improve accessibility and dashboard visualization.
- Add continuous integration to run tests automatically on GitHub.

## 👩‍💻 Author

**Khouloud BM**

Computer Science Student | Cybersecurity & Networking



