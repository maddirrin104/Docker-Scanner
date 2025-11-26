import argparse
import os
import sys

from tabulate import tabulate

from core.filters import parse_report
from core.tools import run_trivy
from report.csv_writter import export_csv
from report.html_writter import export_html
from report.json_writter import export_json


def count_by_severity(report):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in report:
        sev = (row[2] or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def severity_meets_threshold(found_sev, min_sev):
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    try:
        return order.index(found_sev) >= order.index(min_sev)
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser(description="Docker Scanner Wrapper for Trivy")
    parser.add_argument("command", choices=["scan"], help="Commmand to scan")
    parser.add_argument("image", help="Docker image to scan, E.g., ubuntu:20.04")
    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "html", "csv", "terminal"],
        default="terminal",
    )
    parser.add_argument(
        "-f", "--file", help="Output file name (for json/html formats)", default="report.out"
    )
    parser.add_argument(
        "-s",
        "--severity",
        nargs="+",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter by severity level",
    )

    parser.add_argument(
        "--reprort-dir", default="scan-results", help="Directory to save reports for CI artifacts"
    )
    parser.add_argument(
        "--fail-threshold",
        type=int,
        default=0,
        help="Fail the scan if vulnerabilities found exceed this number",
    )
    parser.add_argument(
        "--fail-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Fail the scan if vulnerabilities of this severity or higher are found",
    )

    args = parser.parse_args()

    outputdir = "scan-results"
    output_path = os.path.join(outputdir, args.file)

    try:
        if args.command == "scan":
            print(f"Scanning image: {args.image} ...\n")
            data = run_trivy(args.image)
            report = parse_report(data, severity_filter=args.severity)

            if not report:
                print("No vulnerabilities found.")
                export_json([], output_path) if args.output in ("json", "html", "csv") else None
                return

            counts = count_by_severity(report)
            total = len(report)

            if args.output == "terminal":
                headers = ["Package", "CVE ID", "Severity", "Installed", "Fixed", "Title"]
                print(tabulate(report, headers=headers, tablefmt="github"))
            elif args.output == "json":
                export_json(report, output_path)
                print(f"Report saved to {output_path} (JSON format)")
            elif args.output == "html":
                export_html(report, output_path)
                print(f"Report saved to {output_path} (HTML format)")
            elif args.output == "csv":
                export_csv(report, output_path)
                print(f"Report saved to {output_path} (CSV format)")
            print(f"\nTotal found: {len(report)} vulnerabilities")
            print("Summary by severity:", counts)

            # Decide CI failure
            failed = False
            if args.fail_threshold and total > args.fail_threshold:
                print(
                    f"Scan failed: {total} vulnerabilities found exceeds threshold of {args.fail_threshold}."
                )
                failed = True

            # Check severity-based failure
            if args.fail_severity:
                for sev, count in counts.items():
                    if severity_meets_threshold(sev, args.fail_severity) and counts.get(sev, 0) > 0:
                        print(
                            f"Scan failed: Found {count} vulnerabilities of severity {sev} or higher."
                        )
                        failed = True
                        break
            if failed:
                print("Failure condition met. Exiting with code 2.")
                return 2

            print("No failure conditions met. Scan successful.")
            return 0

    except Exception as e:
        print("Scanner error: ", e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    main()
