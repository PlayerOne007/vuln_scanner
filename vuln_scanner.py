#!/usr/bin/env python3

import subprocess
import re
import json
import sys
from pathlib import Path

findings = []

IGNORE_DIRS = ["venv", ".venv", ".git", "__pycache__", "node_modules"]


# -------------------------
# 1. SECRET SCANNER
# -------------------------
def scan_secrets(folder):
    patterns = [
        ("HIGH", "AWS Key", r"AKIA[0-9A-Z]{16}"),
        ("HIGH", "Password", r"(?i)password\s*=\s*['\"].+['\"]"),
        ("MEDIUM", "API Key", r"(?i)api[_-]?key\s*=\s*['\"].+['\"]"),
    ]

    print("\n[+] Scanning for secrets...")

    for file in Path(folder).rglob("*"):
        if any(part in IGNORE_DIRS for part in file.parts):
            continue

        if file.is_file() and file.suffix in [".py", ".txt", ".env"]:
            try:
                content = file.read_text(errors="ignore")

                for i, line in enumerate(content.splitlines(), 1):
                    for severity, name, pattern in patterns:
                        if re.search(pattern, line):
                            findings.append({
                                "type": "secret",
                                "severity": severity,
                                "name": name,
                                "file": str(file),
                                "line": i
                            })

                            print(f"[{severity}] {name} found in {file}:{i}")

            except:
                pass


# -------------------------
# 2. BANDIT SCAN (FIXED)
# -------------------------
def scan_bandit(folder):
    print("\n[+] Running Bandit...")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", folder, "-f", "json"],
            capture_output=True,
            text=True
        )

        # Show errors if any
        if result.stderr.strip():
            print("Bandit warning/error:")
            print(result.stderr.strip())

        # If no output
        if not result.stdout.strip():
            print("Bandit did not return JSON output")
            return

        # Try parsing JSON safely
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("Bandit output not valid JSON. Raw output:")
            print(result.stdout)
            return

        for issue in data.get("results", []):
            findings.append({
                "type": "bandit",
                "severity": issue.get("issue_severity", "LOW"),
                "name": issue.get("issue_text", "Bandit issue"),
                "file": issue.get("filename"),
                "line": issue.get("line_number")
            })

        print("[+] Bandit scan complete")

    except Exception as e:
        print(f"Bandit error: {e}")
        print("Install with: pip install bandit")


# -------------------------
# 3. DEPENDENCY SCAN (FIXED)
# -------------------------
def scan_dependencies(folder):
    print("\n[+] Checking dependencies...")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-f", "json"],
            cwd=folder,
            capture_output=True,
            text=True
        )

        if result.stderr.strip():
            print("pip-audit warning:")
            print(result.stderr.strip())

        if not result.stdout.strip():
            print("pip-audit returned no data")
            return

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("pip-audit output not valid JSON")
            print(result.stdout)
            return

        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                findings.append({
                    "type": "dependency",
                    "severity": "HIGH",
                    "name": vuln.get("id", "Known vulnerability"),
                    "file": dep.get("name"),
                    "line": "-"
                })

        print("[+] Dependency scan complete")

    except Exception as e:
        print(f"pip-audit error: {e}")
        print("Install with: pip install pip-audit")


# -------------------------
# 4. SAVE REPORTS
# -------------------------
def save_reports():
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    html = """
<html>
<head>
<title>Vulnerability Report</title>
<style>
body { font-family: Arial; margin: 20px; }
.HIGH { color: red; }
.MEDIUM { color: orange; }
.LOW { color: green; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; }
</style>
</head>
<body>
<h1>Vulnerability Report</h1>
<table>
<tr><th>Severity</th><th>Type</th><th>Name</th><th>File</th><th>Line</th></tr>
"""

    for f in findings:
        html += f"""
<tr>
<td class="{f['severity']}">{f['severity']}</td>
<td>{f['type']}</td>
<td>{f['name']}</td>
<td>{f['file']}</td>
<td>{f['line']}</td>
</tr>
"""

    html += "</table></body></html>"

    with open("report.html", "w", encoding="utf-8") as file:
        file.write(html)

    print("\n[+] Reports saved: report.json, report.html")


# -------------------------
# MAIN
# -------------------------
def main():
    target = input("Enter folder to scan: ")

    if not Path(target).exists():
        print("Folder not found")
        return

    scan_secrets(target)
    scan_bandit(target)
    scan_dependencies(target)

    save_reports()

    print("\nScan complete.")


if __name__ == "__main__":
    main()