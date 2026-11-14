def analyze_website_info(page_title: str, page_text: str):
    risk_score = 0
    warnings = []

    combined_text = f"{page_title} {page_text}".lower()

    sensitive_terms = [
        "password", "otp", "pin", "upi pin", "cvv", "credit card",
        "bank account", "pan card", "aadhaar", "seed phrase", "private key"
    ]
    found_sensitive = [term for term in sensitive_terms if term in combined_text]
    if found_sensitive:
        risk_score += len(found_sensitive) * 12
        warnings.append(f"Page requests sensitive credentials or keys: {', '.join(found_sensitive)}")

    trading_terms = [
        "guaranteed profit", "double your money", "withdrawal frozen",
        "release fee", "unfreeze account", "vip signal", "download apk"
    ]
    found_trading = [term for term in trading_terms if term in combined_text]
    if found_trading:
        risk_score += len(found_trading) * 15
        warnings.append(f"Page exhibits investment scam or APK sideloading indicators: {', '.join(found_trading)}")

    pressure_terms = [
        "act now", "limited time", "verify immediately", "account suspended", "final warning"
    ]
    found_pressure = [term for term in pressure_terms if term in combined_text]
    if found_pressure:
        risk_score += len(found_pressure) * 10
        warnings.append(f"Page employs high-pressure tactics: {', '.join(found_pressure)}")

    login_terms = ["sign in", "log in", "login", "portal", "wallet connect"]
    if any(term in combined_text for term in login_terms):
        warnings.append("Page contains an authentication or wallet login interface")

    return risk_score, warnings