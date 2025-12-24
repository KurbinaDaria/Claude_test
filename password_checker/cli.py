"""CLI interface for the password strength checker."""

import sys
from password_checker.checker import check_password_strength


def main():
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        password = input("Enter a password to check: ")

    result = check_password_strength(password)

    if result.get('is_blacklisted'):
        print("\n" + "=" * 50)
        print("WARNING: BLACKLISTED PASSWORD")
        print("=" * 50)

    print(f"\nPassword Strength: {result['strength']}")
    print(f"Score: {result['score']}/100")
    print(f"Entropy: {result['entropy']} bits")

    if result['feedback']:
        print("\nFeedback:")
        for feedback in result['feedback']:
            print(f"  - {feedback}")


if __name__ == "__main__":
    main()
