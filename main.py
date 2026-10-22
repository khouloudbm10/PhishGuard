
import argparse
import json

from src.detector import analyze_url


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard - Explainable phishing URL risk analyzer"
    )

    parser.add_argument(
        "url",
        help="URL to analyze. The URL will not be opened or visited.",
    )

    args = parser.parse_args()
    result = analyze_url(args.url)

    print("\n=== PhishGuard URL Analysis ===")
    print(f"URL: {result['url']}")
    print(f"Risk level: {result['risk']}")
    print(f"Risk score: {result['score']}/100")

    print("\nFindings:")
    for finding in result["findings"]:
        print(f"  - {finding}")

    print("\nJSON output:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
