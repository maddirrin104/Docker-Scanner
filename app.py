import json
import os
import time
import psutil # type: ignore
from functools import lru_cache

from flask import Flask, flash, redirect, render_template, request, send_from_directory, url_for, g

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

def timed_render(template_name, **context):
    before = time.time()
    rendered = render_template(template_name, **context)
    after = time.time()

    start = getattr(g, "scan_start", before)
    total_time = after - start
    render_time = after - before

    # CPU deltas from request-start snapshot (if any)
    proc = psutil.Process(os.getpid())
    proc_start = getattr(g, "cpu_proc_start", None)
    sys_start = getattr(g, "cpu_sys_start", None)

    proc_now = proc.cpu_times().user + proc.cpu_times().system
    sys_times = psutil.cpu_times()
    sys_now = sys_times.user + sys_times.system

    proc_delta = proc_now - (proc_start or proc_now)
    sys_delta = sys_now - (sys_start or sys_now)

    cpu_count = psutil.cpu_count(logical=True) or 1
    # average system CPU percent during request
    avg_sys_pct = (sys_delta / total_time) / cpu_count * 100 if total_time > 0 else 0.0

    image = context.get("image", "")
    app.logger.info(
        f"Scan timing: image={image} total={total_time:.3f}s render={render_time:.3f}s "
        f"proc_cpu={proc_delta:.3f}s system_cpu={sys_delta:.3f}s avg_sys%={avg_sys_pct:.1f} cpus={cpu_count} path={request.path}"
    )

    return rendered

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
    g.scan_start = time.time()
    # cpu snapshots for whole-request
    proc = psutil.Process(os.getpid())
    g.cpu_proc_start = proc.cpu_times().user + proc.cpu_times().system
    st = psutil.cpu_times()
    g.cpu_sys_start = st.user + st.system

    image = request.form.get("image", "").strip()
    severities = request.form.getlist("severity")

    if not image:
        flash("Please provide an image to scan.", category="error")
        # re-render page with current form values so inputs are preserved
        return timed_render(
            "index.html",
            results=None,
            headers=HEADERS,
            image=image or "",
        )
        
    # Check cache before re-scan
    cached_report, cache_hit = cache_manager.get_cached_report(image, severity_filter=None, fail_threshold=0, fail_severity="")
    if cache_hit and cached_report:
        flash(f"Results from cache (scanned earlier).", category="success")
        return timed_render("index.html", results=cached_report, headers=HEADERS, image=image, from_cache=True)


    # gọi lại chức năng hiện có
    # Measure CPU for the actual scan step
    scan_proc_before = proc.cpu_times().user + proc.cpu_times().system
    scan_sys_before = psutil.cpu_times().user + psutil.cpu_times().system

    try:
        data = run_trivy(image)
    except Exception as e:
        flash(f"Scanner error : {e}", category="error")
        return timed_render(
            "index.html",
            results=None,
            headers=HEADERS,
            image=image or "",
        )
    
    report = parse_report(data, severity_filter=severities if severities else None)

    # after scan
    scan_proc_after = proc.cpu_times().user + proc.cpu_times().system
    scan_sys_after = psutil.cpu_times().user + psutil.cpu_times().system

    scan_proc_delta = scan_proc_after - scan_proc_before
    scan_sys_delta = scan_sys_after - scan_sys_before
    elapsed_scan = time.time() - getattr(g, "scan_start", time.time())
    avg_scan_sys_pct = (scan_sys_delta / max(elapsed_scan, 1e-6)) / (psutil.cpu_count() or 1) * 100

    app.logger.info(
        f"Scan step CPU: image={image} proc_cpu={scan_proc_delta:.3f}s system_cpu={scan_sys_delta:.3f}s "
        f"elapsed_since_start={elapsed_scan:.3f}s avg_sys%={avg_scan_sys_pct:.1f}"
    )

    if not report:
        flash("No vulnerabilities found.", category="success")
        # keep the form values when showing the message
        return timed_render(
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
    return timed_render(
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
    g.scan_start = time.time()            # <-- add this
    # cpu snapshots for whole-request
    proc = psutil.Process(os.getpid())
    g.cpu_proc_start = proc.cpu_times().user + proc.cpu_times().system
    st = psutil.cpu_times()
    g.cpu_sys_start = st.user + st.system

    image = request.form.get("image", "").strip()
    selected_severities = request.form.getlist("severity")
    try:
        fail_threshold = int(request.form.get("fail_threshold", 0))
    except ValueError:
        fail_threshold = 0
    fail_severity = request.form.get("fail_severity", "")

    if not image:
        flash("Please provide an image to scan.", category="error")
        return timed_render(
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
        return timed_render(
            "advanced_scan.html",
            results=cached_report,
            headers=HEADERS,
            selected_severities=selected_severities,
            fail_threshold=fail_threshold,
            fail_severity=fail_severity,
            image=image,
            from_cache=True
        )

    # Measure CPU for the actual scan step
    scan_proc_before = proc.cpu_times().user + proc.cpu_times().system
    scan_sys_before = psutil.cpu_times().user + psutil.cpu_times().system

    try:
        data = run_trivy(image)
    except Exception as e:
        flash(f"Scanner error: {e}", category="error")
        return timed_render(
            "advanced_scan.html",
            results=None,
            headers=HEADERS,
            selected_severities=selected_severities,
            fail_threshold=fail_threshold,
            fail_severity=fail_severity,
            image=image
        )

    report = parse_report(data, severity_filter=selected_severities if selected_severities else None)

    # after scan
    scan_proc_after = proc.cpu_times().user + proc.cpu_times().system
    scan_sys_after = psutil.cpu_times().user + psutil.cpu_times().system

    scan_proc_delta = scan_proc_after - scan_proc_before
    scan_sys_delta = scan_sys_after - scan_sys_before
    elapsed_scan = time.time() - getattr(g, "scan_start", time.time())
    avg_scan_sys_pct = (scan_sys_delta / max(elapsed_scan, 1e-6)) / (psutil.cpu_count() or 1) * 100

    app.logger.info(
        f"Scan step CPU: image={image} proc_cpu={scan_proc_delta:.3f}s system_cpu={scan_sys_delta:.3f}s "
        f"elapsed_since_start={elapsed_scan:.3f}s avg_sys%={avg_scan_sys_pct:.1f}"
    )

    if not report:
        flash("No vulnerabilities found.", category="success")
        return timed_render(
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
        flash(f"Scanning completed, CI failed: {fail_reason}", category="error")
    else:
        flash(f"Scanning completed, CI successful: No failure condition met", category="success")

    return timed_render(
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