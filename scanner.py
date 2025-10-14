import argparse
import json
import subprocess
import sys

from tabulate import tabulate
from bs4 import BeautifulSoup


def run_trivy(image):
    """Run Trivy scan on the specified Docker image, return results as JSON."""
    try:
        # Trước:
        # result = subprocess.run(
        #     ["trivy", "image", "-f", "json", "-q", image],
        #     stdout=subprocess.PIPE,
        #     stderr=subprocess.PIPE,
        #     text=True,
        #     check=True,
        # )
        # Sau (đúng UP022):
        result = subprocess.run(
            ["trivy", "image", "-f", "json", "-q", image],
            capture_output=True,  # thay cho stdout/stderr = PIPE
            text=True,
            check=True,
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
            results.append(
                [
                    vuln.get("PkgName", ""),
                    vuln.get("VulnerabilityID", ""),
                    vuln.get("Severity", ""),
                    vuln.get("InstalledVersion", ""),
                    vuln.get("FixedVersion", ""),
                    vuln.get("Title", "")[:50],
                ]
            )
    return results

def export_json(report, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

def export_html(report, filename):
    headers = ["Package", "CVE ID", "Severity", "Installed", "Fixed", "Title"]
    table = tabulate(report, headers=headers, tablefmt="html")
     # Parse table bằng BeautifulSoup
    soup = BeautifulSoup(table, "html.parser")

    # Duyệt từng dòng (tr trừ header)
    for row in soup.find_all("tr")[1:]:
        cells = row.find_all("td")
        if len(cells) < 3:
            continue
        sev_cell = cells[2]  # Cột thứ 3 là Severity
        sev = sev_cell.text.strip().upper()
        # Gán class và attribute cho CSS dùng
        sev_cell['data-severity'] = sev
        sev_cell['class'] = [f'sev-{sev}']
        # Thêm span badge
        sev_cell.string = ''  # Xóa text cũ
        badge = soup.new_tag('span', **{'class': 'badge'})
        badge.string = sev
        sev_cell.append(badge)

    html =f"""<html>
                <head>
                    <meta charset="utf-8">
                    <title>Vulnerability Report</title>
                    <link rel="stylesheet" href="./report.css" />
                </head>
                <body>
                    <h2>Docker Image Vunerability Report</h2>
                    <p>Total found: {len(report)} vulnerabilities</p>
                    {soup.prettify()}
                </body>
            </html>"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

def export_csv(report, filename):
    headers = ["Package", "CVE ID", "Severity", "Installed", "Fixed", "Title"]
    table = tabulate(report, headers=headers, tablefmt="csv")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(table)

def main():
    parser = argparse.ArgumentParser(description="Docker Scanner Wrapper for Trivy")
    parser.add_argument("command", choices=["scan"], help="Commmand to scan")
    parser.add_argument("image", help="Docker image to scan, E.g., ubuntu:20.04")
    parser.add_argument("-o", "--output", choices=["json", "html", "csv", "terminal"], default="terminal",)
    parser.add_argument("-f", "--file", help="Output file name (for json/html formats)", default="report.out")
    args = parser.parse_args()

    if args.command == "scan":
        print(f"Scanning image: {args.image} ...\n")
        data = run_trivy(args.image)
        report = parse_report(data)

        if not report:
            print("No vulnerabilities found.")
            return
        if args.output == "terminal":
            headers = ["Package", "CVE ID", "Severity", "Installed", "Fixed", "Title"]
            print(tabulate(report, headers=headers, tablefmt="github"))
            print(f"\nTotal found: {len(report)} vulnerabilities")
        elif args.output == "json":
            export_json(report, args.file)
            print(f"Report saved to {args.file} (JSON format)")
            print(f"\nTotal found: {len(report)} vulnerabilities")
        elif args.output == "html":
            export_html(report, args.file)
            print(f"Report saved to {args.file} (HTML format)")
            print(f"\nTotal found: {len(report)} vulnerabilities")
        elif args.output == "csv":
            export_csv(report, args.file)
            print(f"Report saved to {args.file} (CSV format)")
            print(f"\nTotal found: {len(report)} vulnerabilities")


if __name__ == "__main__":
    main()
