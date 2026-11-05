def analyze_website_info(page_title, page_text):
    """
    Analyze user-provided website information for basic warning indicators.
    This function does not access or attack the website.
    """

    risk_score = 0
    warnings = []

    combined_text = f"{page_title} {page_text}".lower()

    # Sensitive information requests
    sensitive_terms = [
        "password", "otp", "pin", "cvv",
        "credit card", "bank account"
    ]

    found_sensitive = [
        term for term in sensitive_terms
        if term in combined_text
    ]

    if found_sensitive:
        risk_score += len(found_sensitive)
        warnings.append(
            "Page requests or mentions sensitive information: "
            + ", ".join(found_sensitive)
        )

    # Pressure language
    pressure_terms = [
        "act now", "limited time", "verify immediately",
        "account suspended", "final warning"
    ]

    found_pressure = [
        term for term in pressure_terms
        if term in combined_text
    ]

    if found_pressure:
        risk_score += len(found_pressure)
        warnings.append(
            "Page uses pressure language: "
            + ", ".join(found_pressure)
        )

    # Basic login page indicator
    login_terms = ["sign in", "log in", "login"]

    found_login = [
        term for term in login_terms
        if term in combined_text
    ]

    if found_login:
        warnings.append(
            "Page appears to contain a login or sign-in request"
        )

    return risk_score, warnings