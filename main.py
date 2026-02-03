# main.py

import argparse

from scanners.bola_scanner import BOLAScanner
from reporting.markdown_report import MarkdownReport
from utils.config_loader import load_config


def main():
    parser = argparse.ArgumentParser(
        description="Smart API Security Scanner"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to config.json",
    )

    args = parser.parse_args()

    config = load_config(args.config)

    scanner = BOLAScanner(config["target"])
    report = MarkdownReport(target=config["target"])

    for resource in config["resources"]:
        for object_id in config["scan"]["object_ids"]:
            result = scanner.scan(
                resource=resource,
                user_a=config["user_a"],
                user_b=config["user_b"],
                object_id=object_id,
            )
            report.add_finding(result)

    output = report.generate()

    with open("api_security_report.md", "w") as f:
        f.write(output)

    print("✅ Scan completed")
    print("📄 Report saved as api_security_report.md")


if __name__ == "__main__":
    main()
