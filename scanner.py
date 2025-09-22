import subprocess
import json
import sys
import argparse
from tabulate import tabulate

def run_trivy(image):
    """Run Trivy scan on the specified Docker image, return results as JSON."""
    try:
        result = subprocess.run(
            ["trivy", "image", "-f", "json", "-q", image],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error while running Trivy: {e.stderr}", file=sys.stderr)
        sys.exit(1)

def parse_report(data: dict):
    """Parse Trivy JSON and extract CVE list."""
    results = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            results.append([
                vuln.get("PkgName", ""),
                vuln.get("VulnerabilityID", ""),
                vuln.get("Severity", ""),
                vuln.get("InstalledVersion", ""),
                vuln.get("FixedVersion", ""),
                vuln.get("Title", "")[:50]
            ])
    return results

def main():
    parser = argparse.ArgumentParser(description="Docker Scanner Wrapper for Trivy")
    parser.add_argument("command", choices=["scan"], help="Commmand to scan")
    parser.add_argument("image", help="Docker image to scan, E.g., ubuntu:20.04")
    args = parser.parse_args()

    if args.command == "scan":
        print(f"Scanning image: {args.image} ...\n")
        data = run_trivy(args.image)
        report = parse_report(data)

        if not report:
            print("No vulnerabilities found.")
            return
        else:
            headers = ["Package", "CVE ID", "Severity", "Installed", "Fixed", "Title"]
            print(tabulate(report, headers=headers, tablefmt="github"))
            print(f"\nTotal found: {len(report)} vulnerabilities")  

if __name__ == "__main__":
    main()