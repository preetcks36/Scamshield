import re
from text_checker import analyze_writing_patterns
from url_checker import analyze_url

CATEGORY_RULES = [
    {
        "category": "Account Threat",
        "weight": 30,
        "pattern": re.compile(
            r"(account\s+(is\s+)?(on\s+hold|suspend(ed)?|locked|restrict(ed)?|blocked)|"
            r"\bon\s+hold\b|unusual\s+(sign-in|activity|transaction)|unauthori[sz]ed\s+access|"
            r"kyc\s+(pending|expired|update|suspended)|service\s+(shut\s+off|disconnect(ed)?|terminat(ed)?)|"
            r"electricity\s+(will\s+be\s+disconnected|power\s+cut|bill\s+overdue)|"
            r"account\s+will\s+be\s+closed|legal\s+action|penalty|terminated)",
            re.IGNORECASE
        ),
        "warning": "Account threat, utility disconnection, or coercive disruption tactic detected"
    },
    {
        "category": "Sensitive Request",
        "weight": 35,
        "pattern": re.compile(
            r"(update\s+.*?(payment|billing|card|account|pan|aadhaar)|"
            r"billing\s+information|payment\s+details|"
            r"link\s+(your\s+)?(pan|aadhaar)|"
            r"verify\s+(your\s+)?(identity|account|details|wallet)|"
            r"(enter|share)\s+(the\s+)?(otp|password|pin|cvv|security\s+code)|"
            r"reply\s+with\s+(the\s+)?code|"
            r"pay\s+(small\s+)?(fee|charges?|shipping|redelivery\s+fee|pending\s+bill)|"
            r"claim\s+(your\s+)?(refund|reward|prize)|"
            r"dispute\s+(charge|transaction)|bank\s+account|credit\s+card)",
            re.IGNORECASE
        ),
        "warning": "Direct request for payment details, credentials, PAN/KYC or OTP verification"
    },
    {
        "category": "Action Pressure",
        "weight": 20,
        "pattern": re.compile(
            r"(update\s+account\s+now|act\s+now|within\s+(12|24|48)\s+hours?|immediately|"
            r"tonight\s+at\s+\d{1,2}(:\d{2})?|by\s+\d{1,2}(:\d{2})?\s*(pm|am)|"
            r"final\s+(notice|warning)|last\s+chance|urgent(ly)?|time[- ]sensitive|"
            r"expir(es?|ing)\s+today|avoid\s+(penalties|suspension|legal\s+action|disconnection)|"
            r"limited\s+time|verify\s+now)",
            re.IGNORECASE
        ),
        "warning": "Coercive urgency, deadline ultimatum, or artificial countdown pressure"
    },
    {
        "category": "Brand Impersonation",
        "weight": 25,
        "pattern": re.compile(
            r"\b(netflix|amazon|usps|fedex|dhl|india\s+post|paypal|apple\s+id|"
            r"geek\s+squad|chase|wellsfargo|mcafee|norton|sbi|yono|hdfc|icici|paytm)\b",
            re.IGNORECASE
        ),
        "warning": "Impersonation of a recognized brand, bank, or utility service"
    },
    {
        "category": "Generic Salutation",
        "weight": 15,
        "pattern": re.compile(
            r"\b(hi\s+dear|dear\s+(customer|user|client|member|cardholder|taxpayer|consumer)|"
            r"dear\s+sir\/madam|valued\s+customer)\b",
            re.IGNORECASE
        ),
        "warning": "Generic greeting indicates bulk untargeted phishing"
    }
]

def analyze_message(message: str):
    risk_score = 0
    warnings = []
    matched_phrases = []
    triggered_categories = []

    for rule in CATEGORY_RULES:
        matches = list(rule["pattern"].finditer(message))
        if matches:
            risk_score += rule["weight"]
            triggered_categories.append(rule["category"])
            warnings.append(rule["warning"])
            for m in matches:
                matched_phrases.append(m.group(0))

    pattern_score, pattern_warnings = analyze_writing_patterns(message)
    risk_score += pattern_score * 5
    warnings.extend(pattern_warnings)

    links = re.findall(r"https?://\S+", message)
    for link in links:
        url_score, url_warnings = analyze_url(link)
        risk_score += url_score
        for w in url_warnings:
            warnings.append(f"Embedded URL ({link[:25]}...): {w}")

    return risk_score, warnings, list(set(matched_phrases)), triggered_categories