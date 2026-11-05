def analyze_screenshot_info(description):
    """
    Analyze a user-provided description of a website screenshot.

    This is a placeholder for future AI-powered image analysis.
    It does not claim to understand the actual image yet.
    """

    risk_score = 0
    warnings = []

    description_lower = description.lower()

    visual_warning_terms = [
        "fake login", "password request",
        "urgent popup", "suspicious popup",
        "brand imitation", "fake website"
    ]

    found_terms = [
        term for term in visual_warning_terms
        if term in description_lower
    ]

    if found_terms:
        risk_score += len(found_terms)
        warnings.append(
            "Possible visual warning signs described: "
            + ", ".join(found_terms)
        )

    return risk_score, warnings