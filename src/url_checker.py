from urllib.parse import urlparse
import re


def check_https(url):
    return url.startswith("https://")


def check_suspicious_keywords(url):
    suspicious_keywords = [
        "login", "verify", "password", "account",
        "secure", "update", "confirm"
    ]
    return [word for word in suspicious_keywords if word in url.lower()]


def check_url_length(url):
    return len(url) > 100


def check_subdomains(url):
    domain = urlparse(url).netloc.split(":")[0]
    parts = domain.split(".")
    return len(parts) > 3


def check_at_symbol(url):
    return "@" in url


def check_ip_address(url):
    domain = urlparse(url).netloc.split(":")[0]
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain))


def analyze_url(url):
    risk_score = 0
    warnings = []

    if not check_https(url):
        risk_score += 2
        warnings.append("Website does not use HTTPS")

    keywords = check_suspicious_keywords(url)
    if keywords:
        risk_score += len(keywords)
        warnings.append(
            "Suspicious keywords found: " + ", ".join(keywords)
        )

    if check_url_length(url):
        risk_score += 1
        warnings.append("URL is unusually long")

    if check_subdomains(url):
        risk_score += 1
        warnings.append("URL contains many subdomains")

    if check_at_symbol(url):
        risk_score += 2
        warnings.append("URL contains an @ symbol")

    if check_ip_address(url):
        risk_score += 2
        warnings.append("URL uses an IP address instead of a domain name")

    return risk_score, warnings