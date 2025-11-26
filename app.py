import json
import os
import time

from flask import Flask, flash, redirect, render_template, request, send_from_directory, url_for

from core.filters import parse_report
from core.tools import run_trivy
from report.csv_writter import export_csv
from report.html_writter import export_html
from report.json_writter import export_json
from scanner import count_by_severity, severity_meets_threshold

BASE_DIR = os.path.dirname(__file__)
OUTPUT_DIR = os.path.join(BASE_DIR, "scan-results")
os.makedirs(OUTPUT_DIR, exist_ok=True)
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
app.secret_key = "NT140-DockerScanner"

HEADERS = ["Package", "CVE ID", "Severity", "Installed", "Fixed", "Title"]


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", results=None, headers=HEADERS)


@app.route("/scan", methods=["POST"])
def scan():
    image = request.form.get("image")
    severities = request.form.getlist("severity")
    fail_threshold = request.form.get("fail_threshold", 0, type=int)
    fail_severity = request.form.get("fail_severity", None)

    if not image:
        flash("Please provide an image to scan.")
        return redirect(url_for("index"))

    # gọi lại chức năng hiện có
    data = run_trivy(image)
    report = parse_report(data, severity_filter=severities if severities else None)

    if not report:
        flash("No vulnerabilities found.")
        return redirect(url_for("index"))

    base = f"{image.replace('/', '_').replace(':', '_')}_{int(time.time())}"
    json_path = os.path.join(OUTPUT_DIR, base + ".json")
    export_json(report, json_path)

    # Check fail conditions
    counts = count_by_severity(report)
    total = len(report)
    failed = False
    fail_reason = ""

    if fail_threshold and total > fail_threshold:
        failed = True
        fail_reason = f"Total vulnerabilities {total} exceed threshold {fail_threshold}."

    if fail_severity:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            if severity_meets_threshold(sev, fail_severity) and counts.get(sev, 0) > 0:
                failed = True
                fail_reason = (
                    f"Found {counts.get(sev, 0)} vulnerabilities of severity {sev} or higher."
                )
                break

    if failed:
        flash(f"Scan failed: {fail_reason}", category="error")
    else:
        flash("Scan successful: No failure conditions met.", category="success")

    return render_template(
        "index.html",
        results=report,
        headers=HEADERS,
        filename=base + ".json",
        image=image,
        selected_severities=severities,
    )


@app.route("/export/<fmt>/<filename>", methods=["GET"])
def export_report(fmt, filename):
    base = os.path.splitext(filename)[0]
    json_path = os.path.join(OUTPUT_DIR, base + ".json")
    if not os.path.exists(json_path):
        flash("Report not found.")
        return redirect(url_for("index"))

    with open(json_path, encoding="utf-8") as f:
        report = json.load(f)

    out_name = f"{base}.{fmt}"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    if fmt == "json":
        export_json(report, out_path)
    elif fmt == "html":
        export_html(report, out_path)
    elif fmt == "csv":
        export_csv(report, out_path)
    else:
        flash("Unsupported format.")
        return redirect(url_for("index"))

    return send_from_directory(OUTPUT_DIR, out_name, as_attachment=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8686, debug=True)
