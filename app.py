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
from caching_result.cache_manager import CacheManager
from caching_result.db import init_db
cache_manager = CacheManager(cache_expire_hours=24)
init_db()

BASE_DIR = os.path.dirname(__file__)
OUTPUT_DIR = os.path.join(BASE_DIR, "scan-results")
os.makedirs(OUTPUT_DIR, exist_ok=True)
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
app.secret_key = "NT140-DockerScanner"

HEADERS = ["Package", "CVE ID", "Severity", "Installed", "Fixed", "Title"]


@app.route("/", methods=["GET"])
def index():
    # provide default values so template inputs have initial state
    return render_template(
        "index.html",
        results=None,
        headers=HEADERS,
        selected_severities=[],
        fail_threshold=0,
        fail_severity="",
        image="",
    )


@app.route("/scan", methods=["POST"])
def scan():
    image = request.form.get("image", "").strip()
    severities = request.form.getlist("severity")

    if not image:
        flash("Please provide an image to scan.", category="error")
        # re-render page with current form values so inputs are preserved
        return render_template(
            "index.html",
            results=None,
            headers=HEADERS,
            image=image or "",
        )
        
    # Check cache before re-scan
    cached_report, cache_hit = cache_manager.get_cached_report(image, severity_filter=None, fail_threshold=0, fail_severity="")
    if cache_hit and cached_report:
        flash(f"Results from cache (scanned earlier).", category="success")
        return render_template("index.html", results=cached_report, headers=HEADERS, image=image, from_cache=True)


    # gọi lại chức năng hiện có
    try:
        data = run_trivy(image)
    except Exception as e:
        flash(f"Scanner error : {e}", category="error")
        return render_template(
            "index.html",
            results=None,
            headers=HEADERS,
            image=image or "",
        )
    
    report = parse_report(data, severity_filter=severities if severities else None)

    if not report:
        flash("No vulnerabilities found.", category="success")
        # keep the form values when showing the message
        return render_template(
            "index.html",
            results=None,
            headers=HEADERS,
            image=image,
        )

    base = f"{image.replace('/', '_').replace(':', '_')}_{int(time.time())}"
    json_path = os.path.join(OUTPUT_DIR, base + ".json")
    export_json(report, json_path)
    cache_manager.save_cache(image, report, json_path, severity_filter=None)
    flash("Scan completed successfully.", category="success")
    return render_template(
        "index.html",
        results=report,
        headers=HEADERS,
        image=image,
    )

@app.route("/advanced-scan", methods=["GET"])
def advanced_scan():
    return render_template(
        "advanced_scan.html",
        results=None,
        headers=HEADERS,
        selected_severities=[],
        fail_threshold=0,
        fail_severity="",
        image=""
    )

@app.route("/scan-advanced", methods=["POST"])
def scan_advanced():
    image = request.form.get("image", "").strip()
    selected_severities = request.form.getlist("severity")
    try:
        fail_threshold = int(request.form.get("fail_threshold", 0))
    except ValueError:
        fail_threshold = 0
    fail_severity = request.form.get("fail_severity", "")

    if not image:
        flash("Please provide an image to scan.", category="error")
        return render_template(
            "advanced_scan.html",
            results=None,
            headers=HEADERS,
            selected_severities=selected_severities,
            fail_threshold=fail_threshold,
            fail_severity=fail_severity,
            image=image
        )
    
    # Check cache before re-scan
    cached_report, cache_hit = cache_manager.get_cached_report(
        image, 
        severity_filter=selected_severities, 
        fail_threshold=fail_threshold, 
        fail_severity=fail_severity
    )
    if cache_hit and cached_report:
        flash(f"Results from cache (scanned earlier).", category="success")
        return render_template(
            "advanced_scan.html",
            results=cached_report,
            headers=HEADERS,
            selected_severities=selected_severities,
            fail_threshold=fail_threshold,
            fail_severity=fail_severity,
            image=image,
            from_cache=True
        )

    try:
        data = run_trivy(image)
    except Exception as e:
        flash(f"Scanner error: {e}", category="error")
        return render_template(
            "advanced_scan.html",
            results=None,
            headers=HEADERS,
            selected_severities=selected_severities,
            fail_threshold=fail_threshold,
            fail_severity=fail_severity,
            image=image
        )

    report = parse_report(data, severity_filter=selected_severities if selected_severities else None)

    if not report:
        flash("No vulnerabilities found.", category="success")
        return render_template(
            "advanced_scan.html",
            results=None,
            headers=HEADERS,
            selected_severities=selected_severities,
            fail_threshold=fail_threshold,
            fail_severity=fail_severity,
            image=image
        )

    base = f"{image.replace('/', '_').replace(':', '_')}_{int(time.time())}"
    json_path = os.path.join(OUTPUT_DIR, base + ".json")
    export_json(report, json_path)

    # Save to cache
    cache_manager.save_cache(
        image, 
        report, 
        json_path, 
        severity_filter=selected_severities, 
        fail_threshold=fail_threshold, 
        fail_severity=fail_severity
    )

    # Check fail conditions
    counts = count_by_severity(report)
    total = len(report)
    failed = False
    fail_reason = ""

    if fail_threshold and total >= fail_threshold:
        failed = True
        fail_reason = f"Total vulnerabilities ({total}) >= threshold ({fail_threshold})"
    
    if fail_severity:
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
            if severity_meets_threshold(sev, fail_severity) and counts.get(sev,0) > 0:
                failed = True
                fail_reason = f"Found {counts.get(sev,0)} {sev} >= fail-severity {fail_severity}"
                break

    if failed:
        flash(f"Scan failed: {fail_reason}", category="error")
    else:
        flash(f"Scan successful: No failure condition met", category="success")

    return render_template(
        "advanced_scan.html",
        results=report,
        headers=HEADERS,
        filename=base + ".json",
        image=image,
        selected_severities=selected_severities,
        fail_threshold=fail_threshold,
        fail_severity=fail_severity
    )

@app.route("/history", methods=["GET"])
def history():
    return render_template("history.html")


@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


@app.route("/signup", methods=["GET"])
def signup():
    return render_template("signup.html")

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
    app.run(host="127.0.0.1", port=3636, debug=True)