from tabulate import tabulate

def export_csv(report, filename):
    headers = ["Package", "CVE ID", "Severity", "Installed", "Fixed", "Title"]
    table = tabulate(report, headers=headers, tablefmt="csv")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(table)