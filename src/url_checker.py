import re
import time
from urllib.parse import urlparse
from functools import lru_cache
from difflib import SequenceMatcher
import requests

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".live", ".cyou", ".ru", ".club",
    ".work", ".click", ".fit", ".site", ".online", ".vip", ".win"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "goo.gl", "cutt.ly", "ow.ly"
}

TARGET_BRANDS = [
    "netflix", "paypal", "amazon", "apple", "microsoft", "google",
    "usps", "fedex", "dhl", "indiapost", "bluedart", "delhivery",
    "sbi", "hdfc", "icici", "axisbank", "paytm", "phonepe", "gpay",
    "zerodha", "groww", "upstox", "binance", "wazirx", "irctc", "uidai", "epfo"
]

OFFICIAL_DOMAINS = {
    "netflix.com", "paypal.com", "amazon.com", "amazon.in", "apple.com",
    "microsoft.com", "google.com", "usps.com", "fedex.com", "dhl.com",
    "indiapost.gov.in", "bluedart.com", "delhivery.com", "sbi.co.in",
    "hdfcbank.com", "icicibank.com", "axisbank.com", "paytm.com",
    "phonepe.com", "zerodha.com", "groww.in", "upstox.com", "binance.com",
    "wazirx.com", "irctc.co.in", "uidai.gov.in", "epfindia.gov.in"
}


def get_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.split(":")[0]


@lru_cache(maxsize=1024)
def _cached_urlhaus_lookup(url: str, time_bucket: int):
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=4
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                return True, data.get("threat", "malware_download")
    except Exception:
        pass
    return False, None


def check_urlhaus(url: str):
    bucket = int(time.time() // 3600)
    return _cached_urlhaus_lookup(url, bucket)


def detect_typosquatting(domain: str):
    if domain in OFFICIAL_DOMAINS or any(domain.endswith("." + od) for od in OFFICIAL_DOMAINS):
        return None

    base_label = domain.split(".")[0]
    cleaned_label = re.sub(r"[^a-z0-9]", "", base_label)

    for brand in TARGET_BRANDS:
        if brand in cleaned_label and domain not in OFFICIAL_DOMAINS:
            return f"Domain embeds protected brand '{brand}' outside official infrastructure"

        normalized = (
            cleaned_label.replace("1", "l")
            .replace("0", "o")
            .replace("rn", "m")
            .replace("vv", "w")
        )
        ratio = SequenceMatcher(None, normalized, brand).ratio()
        if 0.78 <= ratio < 1.0:
            return f"Lookalike / typosquatted domain resembling '{brand}'"

    return None


def analyze_url(url: str):
    risk_score = 0
    warnings = []

    raw_lower = url.strip().lower()
    domain = get_domain(url)

    if raw_lower.endswith(".apk") or ".apk?" in raw_lower:
        risk_score += 45
        warnings.append("Direct Android APK executable download link detected")

    if raw_lower.startswith("http://"):
        risk_score += 15
        warnings.append("Unencrypted HTTP connection (lacks TLS/SSL security)")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        risk_score += 30
        warnings.append("URL uses a raw IP address instead of a registered domain name")

    if domain in URL_SHORTENERS:
        risk_score += 25
        warnings.append(f"Obfuscated URL shortener ({domain}) conceals true destination")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk_score += 20
        warnings.append("Domain uses a high-risk or low-reputation top-level domain (TLD)")

    if domain.count("-") >= 2:
        risk_score += 15
        warnings.append("Excessive hyphens in domain name (common phishing pattern)")

    spoof_warning = detect_typosquatting(domain)
    if spoof_warning:
        risk_score += 35
        warnings.append(spoof_warning)

    is_malicious, threat_type = check_urlhaus(url)
    if is_malicious:
        risk_score += 50
        warnings.append(f"Flagged by Abuse.ch URLhaus Threat Feed ({threat_type})")

    return risk_score, warnings