from bs4 import BeautifulSoup
from tabulate import tabulate


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
        sev_cell["data-severity"] = sev
        sev_cell["class"] = [f"sev-{sev}"]
        # Thêm span badge
        sev_cell.string = ""  # Xóa text cũ
        badge = soup.new_tag("span", **{"class": "badge"})
        badge.string = sev
        sev_cell.append(badge)

    html = f"""<html>
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
