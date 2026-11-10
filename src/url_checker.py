import re
from urllib.parse import urlparse
from functools import lru_cache
import difflib
import requests

TARGET_BRANDS = [
    "netflix", "paypal", "amazon", "apple", "microsoft", 
    "google", "chase", "wellsfargo", "fedex", "usps", "dhl",
    "sbi", "hdfc", "icici"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".live", ".cyou", ".ru", ".club", 
    ".work", ".click", ".fit", ".site", ".online", ".support", ".vip"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"
}

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

def get_domain(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.netloc.split("@")[-1].split(":")[0].lower()
    except Exception:
        return ""

def check_brand_spoofing(domain: str):
    """
    Standard-library brand spoofing and typosquatting detection using difflib.
    No external libraries required.
    """
    domain_clean = domain.split(".")[0] if "." in domain else domain
    domain_normalized = (
        domain_clean.replace("0", "o")
                    .replace("1", "l")
                    .replace("-", "")
    )
    
    for brand in TARGET_BRANDS:
        # Direct exact match on official domain is legitimate
        if domain == f"{brand}.com" or domain.endswith(f".{brand}.com"):
            continue

        # Substring or homoglyph presence
        if brand in domain_normalized:
            return True, f"Possible brand impersonation of '{brand}' inside '{domain}'"

        # Similarity score via built-in difflib SequenceMatcher
        similarity = difflib.SequenceMatcher(None, domain_clean, brand).ratio()
        if 0.78 <= similarity < 1.0:
            return True, f"Lookalike domain detected: '{domain}' is deceptively similar to brand '{brand}'"

    return False, None

@lru_cache(maxsize=512)
def check_urlhaus_cached(url: str):
    """
    Query the free URLhaus threat intelligence API with LRU memory caching.
    """
    try:
        data = {"url": url}
        response = requests.post(URLHAUS_API_URL, data=data, timeout=2.5)
        if response.status_code == 200:
            result = response.json()
            query_status = result.get("query_status")

            if query_status == "ok":
                threat = result.get("threat", "malware")
                url_status = result.get("url_status", "active")
                tags = result.get("tags") or []
                tag_str = f" [{', '.join(tags)}]" if tags else ""
                return True, f"URLhaus Threat Alert: Confirmed {url_status} {threat} distribution site{tag_str}", url_status
    except Exception:
        return False, None, "error"

    return False, None, "clean"

def analyze_url(url: str):
    risk_score = 0
    warnings = []
    
    clean_url = url.strip()
    domain = get_domain(clean_url)

    # 1. URLhaus External Threat Intel
    is_threat, threat_warning, url_status = check_urlhaus_cached(clean_url)
    if is_threat:
        risk_score += 70 if url_status == "online" else 50
        warnings.append(f"🚨 {threat_warning}")

    # 2. HTTPS Check
    if not clean_url.lower().startswith("https://"):
        risk_score += 25
        warnings.append("Website does not enforce HTTPS encryption")

    # 3. Raw IP Check
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        risk_score += 40
        warnings.append("URL uses a raw IP address instead of a domain name")

    # 4. Shortener Check
    if domain in URL_SHORTENERS:
        risk_score += 30
        warnings.append(f"URL uses a link shortener ({domain}) that obscures the destination")

    # 5. Suspicious TLDs
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk_score += 30
        warnings.append("Domain utilizes a high-abuse / suspicious top-level domain (TLD)")

    # 6. Typosquatting / Lookalike Brand Detection
    is_spoofed, reason = check_brand_spoofing(domain)
    if is_spoofed:
        risk_score += 45
        warnings.append(reason)

    # 7. Sensitive Keywords in URL Path
    suspicious_tokens = ["verify", "login", "update", "banking", "secure", "signin", "wallet", "account", "kyc"]
    found_tokens = [tok for tok in suspicious_tokens if tok in clean_url.lower() and tok != domain]
    if found_tokens:
        risk_score += 15
        warnings.append(f"Sensitive keywords in URL path: {', '.join(found_tokens)}")

    return risk_score, warnings