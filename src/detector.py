
from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "signin",
    "banking",
]

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
}


def invalid_result(url: str, message: str) -> dict:
    """Return a consistent result for invalid input."""
    return {
        "url": url,
        "score": 0,
        "risk": "INVALID",
        "findings": [message],
    }


def analyze_url(url: str) -> dict:
    """
    Analyze URL text for common phishing indicators.
    Never opens or visits the submitted URL.

    The score is heuristic, not a probability of phishing.
    """

    if not isinstance(url, str):
        return invalid_result("", "Input must be a string.")

    url = url.strip()

    if not url:
        return {
            "url": url,
            "score": 0,
            "risk": "UNKNOWN",
            "findings": ["No URL provided."],
        }

    # Reject whitespace and control characters inside URLs.
    if any(char.isspace() or ord(char) < 32 for char in url):
        return invalid_result(
            url, "URL contains whitespace or control characters."
        )

    candidate = url if "://" in url else f"https://{url}"

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        port = parsed.port  # Can raise ValueError for malformed ports.
    except ValueError:
        return invalid_result(url, "Malformed URL or network location.")

    if parsed.scheme.lower() not in {"http", "https"}:
        return invalid_result(url, "Only HTTP and HTTPS URLs are supported.")

    if not hostname:
        return invalid_result(url, "URL must contain a hostname.")

    hostname = hostname.lower().rstrip(".")

    # Validate the hostname without making a network request.
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
        ipaddress.ip_address(ascii_hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False
        ascii_hostname = hostname.encode("idna").decode("ascii")

    if len(ascii_hostname) > 253:
        return invalid_result(url, "Hostname is too long.")

    if not is_ip_address:
        labels = ascii_hostname.split(".")

        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label
            )
            for label in labels
        ):
            return invalid_result(url, "Hostname format is invalid.")

    findings = []
    score = 0

    # Flag insecure HTTP.
    if parsed.scheme.lower() == "http":
        score += 10
        findings.append("Uses HTTP instead of HTTPS.")

    # Flag IP addresses used as hosts.
    if is_ip_address:
        score += 25
        findings.append("Uses an IP address instead of a domain name.")

    # Flag credentials embedded in the URL.
    if parsed.username is not None or parsed.password is not None:
        score += 25
        findings.append("Contains embedded URL credentials.")

    # Flag unusually long URLs.
    if len(url) > 100:
        score += 10
        findings.append("Unusually long URL.")

    # Search the hostname and path, not the query or fragment.
    inspected_text = f"{hostname}{parsed.path}"
    keyword_matches = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(
            rf"{re.escape(keyword)}",
            inspected_text,
            re.IGNORECASE,
        )
    ]

    if keyword_matches:
        score += min(20, len(keyword_matches) * 5)
        findings.append(
            "Contains potentially sensitive keywords: "
            + ", ".join(keyword_matches)
        )

    # Flag known shortener domains.
    if ascii_hostname in SHORTENER_DOMAINS:
        score += 15
        findings.append("Uses a URL-shortening service.")

    # Flag unusually many hostname labels.
    if not is_ip_address and len(ascii_hostname.split(".")) > 4:
        score += 15
        findings.append(
            "Contains an unusually high number of domain labels."
        )

    score = min(score, 100)

    if score >= 50:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    if not findings:
        findings.append(
            "No configured warning indicators were detected."
        )

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "findings": findings,
    }
