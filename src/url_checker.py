from urllib.parse import urlparse
import re


def get_domain(url):
    """Extract the domain from a URL."""
    return urlparse(url).netloc.split("@")[-1].split(":")[0].lower()


def check_https(url):
    return url.lower().startswith("https://")


def check_suspicious_keywords(url):
    suspicious_keywords = [
        "login", "verify", "password", "account",
        "secure", "update", "confirm", "wallet",
        "payment", "bonus"
    ]
    return [word for word in suspicious_keywords if word in url.lower()]


def check_url_length(url):
    return len(url) > 100


def check_subdomains(url):
    domain = get_domain(url)
    parts = domain.split(".")
    return len(parts) > 3


def check_at_symbol(url):
    return "@" in url


def check_ip_address(url):
    domain = get_domain(url)
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain))


def check_excessive_numbers(url):
    domain = get_domain(url)
    return sum(char.isdigit() for char in domain) >= 4


def check_many_hyphens(url):
    domain = get_domain(url)
    return domain.count("-") >= 2


def check_encoded_characters(url):
    return "%" in url


def check_url_shortener(url):
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "cutt.ly", "rb.gy"
    ]
    domain = get_domain(url)
    return domain in shorteners


def analyze_url(url):
    risk_score = 0
    warnings = []

    if not check_https(url):
        risk_score += 2
        warnings.append("Website does not use HTTPS")

    keywords = check_suspicious_keywords(url)
    if keywords:
        risk_score += min(len(keywords), 3)
        warnings.append(
            "Potentially sensitive or suspicious words in URL: "
            + ", ".join(keywords)
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

    if check_excessive_numbers(url):
        risk_score += 1
        warnings.append("Domain contains an unusual number of digits")

    if check_many_hyphens(url):
        risk_score += 1
        warnings.append("Domain contains multiple hyphens")

    if check_encoded_characters(url):
        risk_score += 1
        warnings.append("URL contains encoded characters")

    if check_url_shortener(url):
        risk_score += 1
        warnings.append("URL uses a shortened link that hides the destination")

    return risk_score, warnings