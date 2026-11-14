import re
from text_checker import analyze_writing_patterns
from url_checker import analyze_url

CATEGORY_RULES = [
    {
        "category": "Investment & Trading Fraud",
        "weight": 40,
        "pattern": re.compile(
            r"(invest\s+(just\s+|only\s+)?(rs\.?|₹|\$)?\s*\d[\d,]*.*?(double|2x|3x|10x|profit|return)|"
            r"(double|triple)\s+(your\s+)?(money|investment|capital|funds)|"
            r"(guaranteed|assured|100%|daily)\s+(profit|returns?|roi|income)|"
            r"(vip|premium|whatsapp|telegram)\s+(trading|stock|crypto|forex|binary|signal)\s*(group|channel|mentor|professor)|"
            r"(profit|earning|withdrawal)\s+(screenshot|proof)|"
            r"minimum\s+(investment|deposit)\s+(rs\.?|₹|\$)?\s*\d[\d,]*|"
            r"(usdt|binance|crypto|forex|intraday|option\s+trading)\s+(signal|guaranteed|recovery))",
            re.IGNORECASE
        ),
        "warning": "Fake trading / crypto investment scam or guaranteed-return signal lure detected"
    },
    {
        "category": "Malware & APK Sideloading",
        "weight": 40,
        "pattern": re.compile(
            r"(\.apk\b|download\s+(the\s+)?app\s+(via|from)\s+link|"
            r"unknown\s+sources|install\s+(this\s+)?(update|file|app|certificate)|"
            r"(rto|e-?challan|traffic\s+challan|wedding\s+invitation|pm\s+kisan|yojana|trading\s+app).*?\.apk|"
            r"\b(anydesk|teamviewer|quicksupport|rustdesk|screen\s*shar(e|ing))\b)",
            re.IGNORECASE
        ),
        "warning": "High-risk APK sideloading or remote-access screen-sharing lure detected"
    },
    {
        "category": "Account Threat",
        "weight": 30,
        "pattern": re.compile(
            r"((account|wallet|withdrawal|funds?|balance)\s+(is\s+|has\s+been\s+)?(on\s+hold|suspend(ed)?|locked|restrict(ed)?|blocked|froz(en|e)|freez(e|ed))|"
            r"\bon\s+hold\b|unusual\s+(sign-in|activity|transaction)|unauthori[sz]ed\s+access|"
            r"(kyc|pan|aadhaar|fastag|sim(\s+card)?)\s+(pending|expired|update|suspended|blocked|blacklisted)|"
            r"service\s+(shut\s+off|disconnect(ed)?|terminat(ed)?)|"
            r"electricity\s+(will\s+be\s+disconnected|power\s+cut|bill\s+overdue)|"
            r"(digital\s+arrest|parcel\s+(seized|held)|customs\s+clearance|arrest\s+warrant|fir\s+registered)|"
            r"account\s+will\s+be\s+closed|legal\s+action|penalty|terminated)",
            re.IGNORECASE
        ),
        "warning": "Account/withdrawal freeze, utility/SIM cutoff, or legal/digital-arrest coercion detected"
    },
    {
        "category": "Sensitive Request",
        "weight": 35,
        "pattern": re.compile(
            r"(update\s+.*?(payment|billing|card|account|pan|aadhaar|kyc)|"
            r"billing\s+information|payment\s+details|"
            r"link\s+(your\s+)?(pan|aadhaar)|"
            r"verify\s+(your\s+)?(identity|account|details|wallet|upi)|"
            r"(enter|share)\s+(the\s+|your\s+)?(upi\s+pin|otp|password|pin|cvv|security\s+code)|"
            r"(upi\s+pin|qr\s+code|collect\s+request).*?(receive|claim|cashback|refund|credit)|"
            r"(approve|accept)\s+(the\s+)?(payment|collect)\s+request|"
            r"reply\s+with\s+(the\s+)?code|"
            r"pay\s+(small\s+|additional\s+|more\s+)?(fee|charges?|tax|gst|commission|deposit|shipping|redelivery\s+fee|pending\s+bill|customs\s+duty)|"
            r"(withdrawal|release|unfreeze|unlock|clearance|processing)\s+(fee|tax|charge|deposit)|"
            r"(to\s+)?(unfreeze|release|unlock|withdraw)\s+(your\s+)?(whole\s+|full\s+|total\s+)?(money|funds?|balance|profit)|"
            r"claim\s+(your\s+)?(refund|reward|prize|cashback)|"
            r"dispute\s+(charge|transaction)|bank\s+account|credit\s+card)",
            re.IGNORECASE
        ),
        "warning": "Advance-fee withdrawal extortion or direct request for UPI PIN/QR, credentials, or KYC"
    },
    {
        "category": "Employment & Task Fraud",
        "weight": 35,
        "pattern": re.compile(
            r"((part[- ]time|work\s+from\s+home|wfh|online)\s+(job|work|income|earning)|"
            r"earn\s+(rs\.?|₹|\$)\s*\d[\d,]*\s*(per\s+day|daily|weekly|hourly)|"
            r"(like|subscribe|rate|review)\s+(youtube\s+videos?|google\s+maps|hotels?|products?)|"
            r"(prepaid\s+task|merchant\s+task|telegram\s+(hr|mentor|receptionist))|"
            r"no\s+(experience|investment)\s+required.*?daily\s+payout)",
            re.IGNORECASE
        ),
        "warning": "Fake work-from-home task scam or fraudulent recruitment lure detected"
    },
    {
        "category": "Action Pressure",
        "weight": 20,
        "pattern": re.compile(
            r"(update\s+account\s+now|act\s+now|within\s+(2|12|24|48)\s+hours?|immediately|"
            r"tonight\s+at\s+\d{1,2}(:\d{2})?|by\s+\d{1,2}(:\d{2})?\s*(pm|am)|"
            r"final\s+(notice|warning)|last\s+chance|urgent(ly)?|time[- ]sensitive|"
            r"expir(es?|ing)\s+today|avoid\s+(penalties|suspension|legal\s+action|disconnection|block)|"
            r"limited\s+time|verify\s+now)",
            re.IGNORECASE
        ),
        "warning": "Coercive urgency, deadline ultimatum, or artificial countdown pressure"
    },
    {
        "category": "Brand Impersonation",
        "weight": 25,
        "pattern": re.compile(
            r"\b(netflix|amazon|usps|fedex|dhl|india\s+post|bluedart|delhivery|dtdc|"
            r"paypal|apple\s+id|geek\s+squad|chase|wellsfargo|mcafee|norton|"
            r"sbi|yono|hdfc|icici|axis\s+bank|pnb|paytm|gpay|google\s+pay|phonepe|bhim|"
            r"zerodha|groww|upstox|angel\s+one|binance|wazirx|coindcx|"
            r"epfo|uidai|irctc|jio|airtel|trai|cbi|rto)\b",
            re.IGNORECASE
        ),
        "warning": "Impersonation of a recognized brand, broker, bank, courier, or government agency"
    },
    {
        "category": "Generic Salutation",
        "weight": 15,
        "pattern": re.compile(
            r"\b(hi\s+dear|dear\s+(customer|user|client|member|cardholder|taxpayer|consumer|applicant|candidate|investor|trader)|"
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