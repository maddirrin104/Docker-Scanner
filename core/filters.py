def parse_report(data: dict, severity_filter=None):
    """Parse Trivy JSON and extract CVE list."""
    results = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "")
            if severity_filter and severity not in severity_filter:
                continue
            results.append(
                [
                    vuln.get("PkgName", ""),
                    vuln.get("VulnerabilityID", ""),
                    severity,
                    vuln.get("InstalledVersion", ""),
                    vuln.get("FixedVersion", ""),
                    vuln.get("Title", "")[:50],
                ]
            )
    return results
