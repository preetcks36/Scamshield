import re
from url_checker import analyze_url
from text_checker import analyze_writing_patterns


def find_matches(text, patterns):
    """Return all patterns found in the text."""
    text_lower = text.lower()
    return [pattern for pattern in patterns if pattern in text_lower]


def analyze_message(message):
    risk_score = 0
    warnings = []

    message_lower = message.lower()

    # 1. Urgency and pressure tactics
    urgent_words = [
        "urgent", "immediately", "act now", "limited time",
        "suspended", "verify now", "final warning",
        "within 24 hours", "expire"
    ]
    found_urgent = find_matches(message_lower, urgent_words)

    if found_urgent:
        risk_score += len(found_urgent)
        warnings.append(
            "Urgency or pressure language: " + ", ".join(found_urgent)
        )

    # 2. Threatening language
    threat_words = [
        "account will be closed", "legal action",
        "penalty", "blocked", "terminated"
    ]
    found_threats = find_matches(message_lower, threat_words)

    if found_threats:
        risk_score += 2 * len(found_threats)
        warnings.append(
            "Threatening language: " + ", ".join(found_threats)
        )

    # 3. Sensitive information requests
    sensitive_words = [
        "password", "otp", "pin", "credit card",
        "bank account", "cvv", "security code"
    ]
    found_sensitive = find_matches(message_lower, sensitive_words)

    if found_sensitive:
        risk_score += 2 * len(found_sensitive)
        warnings.append(
            "Request for sensitive information: "
            + ", ".join(found_sensitive)
        )

    # 4. Too-good-to-be-true offers
    offer_words = [
        "you won", "claim your prize", "free money",
        "guaranteed profit", "congratulations",
        "selected winner"
    ]
    found_offers = find_matches(message_lower, offer_words)

    if found_offers:
        risk_score += 2 * len(found_offers)
        warnings.append(
            "Possible unrealistic offer: " + ", ".join(found_offers)
        )

    # 5. Writing-pattern analysis
    pattern_score, pattern_warnings = analyze_writing_patterns(message)

    risk_score += pattern_score
    warnings.extend(pattern_warnings)

    # 6. Extract and analyze links
    links = re.findall(r"https?://\S+", message)

    if links:
        warnings.append("Links found: " + ", ".join(links))

        for link in links:
            url_score, url_warnings = analyze_url(link)
            risk_score += url_score

            for warning in url_warnings:
                warnings.append(
                    f"Link warning ({link}): {warning}"
                )

    return risk_score, warnings