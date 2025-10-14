import argparse
import json
import subprocess
import sys
import os

from tabulate import tabulate
from report.json_writter import export_json
from report.html_writter import export_html
from report.csv_writter import export_csv
from core.tools import run_trivy
from core.filters import parse_report

def main():
    parser = argparse.ArgumentParser(description="Docker Scanner Wrapper for Trivy")
    parser.add_argument("command", choices=["scan"], help="Commmand to scan")
    parser.add_argument("image", help="Docker image to scan, E.g., ubuntu:20.04")
    parser.add_argument("-o", "--output", choices=["json", "html", "csv", "terminal"], default="terminal",)
    parser.add_argument("-f", "--file", help="Output file name (for json/html formats)", default="report.out")
    parser.add_argument("-s", "--severity", nargs="+", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Filter by severity level")
    args = parser.parse_args()

    outputdir = "scan-results"
    output_path = os.path.join(outputdir, args.file)

    if args.command == "scan":
        print(f"Scanning image: {args.image} ...\n")
        data = run_trivy(args.image)
        report = parse_report(data, severity_filter=args.severity)

        if not report:
            print("No vulnerabilities found.")
            return
        if args.output == "terminal":
            headers = ["Package", "CVE ID", "Severity", "Installed", "Fixed", "Title"]
            print(tabulate(report, headers=headers, tablefmt="github"))
            print(f"\nTotal found: {len(report)} vulnerabilities")
        elif args.output == "json":
            export_json(report, output_path)
            print(f"Report saved to {output_path} (JSON format)")
            print(f"\nTotal found: {len(report)} vulnerabilities")
        elif args.output == "html":
            export_html(report, output_path)
            print(f"Report saved to {output_path} (HTML format)")
            print(f"\nTotal found: {len(report)} vulnerabilities")
        elif args.output == "csv":
            export_csv(report, output_path)
            print(f"Report saved to {output_path} (CSV format)")
            print(f"\nTotal found: {len(report)} vulnerabilities")


if __name__ == "__main__":
    main()
