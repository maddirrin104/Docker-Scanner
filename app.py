import os
import time
import json
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash
from core.tools import run_trivy
from core.filters import parse_report
from report.json_writter import export_json
from report.html_writter import export_html
from report.csv_writter import export_csv
from tabulate import tabulate

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

    return render_template("index.html", results=report, headers=HEADERS, filename=base + ".json", image=image, selected_severities=severities)

@app.route("/export/<fmt>/<filename>", methods=["GET"])
def export_report(fmt, filename):
    base = os.path.splitext(filename)[0]
    json_path = os.path.join(OUTPUT_DIR, base + ".json")
    if not os.path.exists(json_path):
        flash("Report not found.")
        return redirect(url_for("index"))

    with open(json_path, "r", encoding="utf-8") as f:
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