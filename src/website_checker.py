def analyze_website_info(page_title: str, page_text: str):
    risk_score = 0
    warnings = []

    combined_text = f"{page_title} {page_text}".lower()

    sensitive_terms = [
        "password", "otp", "pin", "cvv", "credit card", "bank account", "social security"
    ]
    found_sensitive = [term for term in sensitive_terms if term in combined_text]
    if found_sensitive:
        risk_score += len(found_sensitive) * 10
        warnings.append(f"Page requests sensitive information: {', '.join(found_sensitive)}")

    pressure_terms = [
        "act now", "limited time", "verify immediately", "account suspended", "final warning"
    ]
    found_pressure = [term for term in pressure_terms if term in combined_text]
    if found_pressure:
        risk_score += len(found_pressure) * 10
        warnings.append(f"Page employs high-pressure tactics: {', '.join(found_pressure)}")

    login_terms = ["sign in", "log in", "login", "portal"]
    if any(term in combined_text for term in login_terms):
        warnings.append("Page contains an authentication or account login interface")

    return risk_score, warnings