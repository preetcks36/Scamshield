import re


def analyze_message(message):
    risk_score = 0
    warnings = []

    # Urgent or pressure-based language
    urgent_words = [
        "urgent", "immediately", "act now", "limited time",
        "suspended", "verify now", "final warning"
    ]

    found_urgent_words = [
        word for word in urgent_words if word in message.lower()
    ]

    if found_urgent_words:
        risk_score += len(found_urgent_words)
        warnings.append(
            "Urgent or pressure language found: "
            + ", ".join(found_urgent_words)
        )

    # Sensitive information requests
    sensitive_words = [
        "password", "otp", "pin", "credit card",
        "bank account", "cvv"
    ]

    found_sensitive_words = [
        word for word in sensitive_words if word in message.lower()
    ]

    if found_sensitive_words:
        risk_score += 2 * len(found_sensitive_words)
        warnings.append(
            "Request for sensitive information: "
            + ", ".join(found_sensitive_words)
        )

    # Detect links
    links = re.findall(r"https?://\S+", message)

    if links:
        warnings.append(
            "Links found in the message: " + ", ".join(links)
        )

    return risk_score, warnings