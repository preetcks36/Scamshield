from url_checker import analyze_url
from email_checker import analyze_message
from website_checker import analyze_website_info
from image_checker import analyze_screenshot_info


def get_risk_level(risk_score):
    """Return a readable risk level based on the score."""
    if risk_score == 0:
        return "LOW RISK"
    elif risk_score <= 3:
        return "CAUTION"
    else:
        return "HIGH RISK"


def get_recommendation(risk_score):
    """Give a safety recommendation based on the risk score."""
    if risk_score == 0:
        return (
            "No major warning signs were detected. "
            "Always verify the source before sharing sensitive information."
        )

    elif risk_score <= 3:
        return (
            "Proceed with caution. Verify the sender or website independently "
            "before clicking links or sharing personal information."
        )

    else:
        return (
            "High-risk indicators were detected. Avoid clicking suspicious "
            "links and do not share passwords, OTPs, PINs, or banking information."
        )


def print_report(title, risk_score, warnings):
    """Display a consistent ScamShield analysis report."""

    print("\n" + "=" * 55)
    print("SCAMSHIELD - " + title)
    print("=" * 55)

    if warnings:
        print("\nWARNING SIGNS:")
        for warning in warnings:
            print("- " + warning)
    else:
        print("\nNo warning signs were detected.")

    print("\n" + "-" * 55)
    print("Risk Score:", risk_score)
    print("Risk Level:", get_risk_level(risk_score))

    print("\nSAFETY RECOMMENDATION:")
    print(get_recommendation(risk_score))

    print("\nDISCLAIMER:")
    print(
        "ScamShield uses warning indicators and cannot guarantee that "
        "a website, message, or image is safe or fraudulent."
    )

    print("=" * 55)


def show_menu():
    """Display the main application menu."""

    print("\nSCAMSHIELD - DIGITAL SAFETY ANALYZER")
    print("=" * 55)
    print("1. Analyze a URL")
    print("2. Analyze an Email or Message")
    print("3. Analyze Website Information")
    print("4. Analyze Screenshot Description")
    print("5. Exit")


def main():
    """Run the ScamShield application."""

    while True:
        show_menu()
        choice = input("\nChoose an option (1-5): ").strip()

        if choice == "1":
            url = input("Enter a website URL: ").strip()

            risk_score, warnings = analyze_url(url)

            print_report(
                "URL ANALYSIS REPORT",
                risk_score,
                warnings
            )

        elif choice == "2":
            message = input("Paste a message or email: ").strip()

            risk_score, warnings = analyze_message(message)

            print_report(
                "MESSAGE ANALYSIS REPORT",
                risk_score,
                warnings
            )

        elif choice == "3":
            page_title = input("Enter the website page title: ").strip()
            page_text = input("Paste visible website text: ").strip()

            risk_score, warnings = analyze_website_info(
                page_title,
                page_text
            )

            print_report(
                "WEBSITE ANALYSIS REPORT",
                risk_score,
                warnings
            )

        elif choice == "4":
            description = input(
                "Describe the screenshot or visible warning signs: "
            ).strip()

            risk_score, warnings = analyze_screenshot_info(
                description
            )

            print_report(
                "SCREENSHOT ANALYSIS REPORT",
                risk_score,
                warnings
            )

        elif choice == "5":
            print("\nThank you for using ScamShield. Stay safe online!")
            break

        else:
            print(
                "\nInvalid choice. Please select a number from 1 to 5."
            )


if __name__ == "__main__":
    main()