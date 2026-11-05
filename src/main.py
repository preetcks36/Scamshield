from url_checker import analyze_url
from email_checker import analyze_message


def get_risk_level(risk_score):
    if risk_score == 0:
        return "🟢 LOW RISK"
    elif risk_score <= 3:
        return "🟡 CAUTION"
    else:
        return "🔴 HIGH RISK"


def show_menu():
    print("\n🛡️ SCAMSHIELD")
    print("=" * 35)
    print("1. Analyze a URL")
    print("2. Analyze an Email or Message")
    print("3. Exit")


while True:
    show_menu()

    choice = input("\nChoose an option (1-3): ")

    if choice == "1":
        url = input("Enter a website URL: ")
        risk_score, warnings = analyze_url(url)

        print("\n🔗 URL ANALYSIS REPORT")
        print("-" * 35)

        if warnings:
            print("Warning signs:")
            for warning in warnings:
                print("⚠", warning)
        else:
            print("✓ No warning signs were detected.")

        print("-" * 35)
        print("Risk score:", risk_score)
        print("Risk level:", get_risk_level(risk_score))

    elif choice == "2":
        message = input("Paste a message or email: ")
        risk_score, warnings = analyze_message(message)

        print("\n📧 MESSAGE ANALYSIS REPORT")
        print("-" * 35)

        if warnings:
            print("Warning signs:")
            for warning in warnings:
                print("⚠", warning)
        else:
            print("✓ No warning signs were detected.")

        print("-" * 35)
        print("Risk score:", risk_score)
        print("Risk level:", get_risk_level(risk_score))

    elif choice == "3":
        print("\nThank you for using ScamShield. Stay safe online! 🛡️")
        break

    else:
        print("\nInvalid choice. Please select 1, 2, or 3.")