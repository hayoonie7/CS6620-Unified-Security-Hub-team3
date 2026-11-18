
import re
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone


# Security patterns to identify potential vulnerabilities
SECURITY_RULES = [
    {
        "name": "Hardcoded Password",
        "pattern": r"""(?i)(password|passwd)\s*=\s*["'][^"']+["']""",
        "severity": "HIGH"
    },
    {
        "name": "Hardcoded API Key",
        "pattern": r"""(?i)(api_key|apikey|secret_key)\s*=\s*["'][^"']+["']""",
        "severity": "HIGH"
    },
    {
        "name": "Use of eval()",
        "pattern": r'\beval\s*\(',
        "severity": "HIGH"
    },
    {
        "name": "Use of exec()",
        "pattern": r'\bexec\s*\(',
        "severity": "HIGH"
    },
    {
        "name": "Dangerous Shell Execution",
        "pattern": r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
        "severity": "HIGH"
    },
    {
        "name": "Potential SQL Injection",
        "pattern": r"""(?i)(execute|executemany)\s*\([^)]*(%s|\.format\s*\(|f["'])""",
        "severity": "MEDIUM"
    }
]


def scan_file(file_path):
    findings = []

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for rule in SECURITY_RULES:
                if re.search(rule["pattern"], line):
                    findings.append({
                        "file": str(file_path),
                        "line": line_number,
                        "vulnerability": rule["name"],
                        "severity": rule["severity"],
                        "description": f"{rule['name']} detected."
                    })

    except OSError as error:
        print(f"Could not read {file_path}: {error}")

    return findings


def scan_directory(directory):
    all_findings = []

    for file_path in Path(directory).rglob("*.py"):
        all_findings.extend(scan_file(file_path))

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Unified Security Hub - SAST Scanner"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Directory containing Python source files to scan"
    )

    parser.add_argument(
        "--output",
        default="sast_report.json",
        help="Output JSON report filename"
    )

    args = parser.parse_args()

    target = Path(args.target)

    if not target.is_dir():
        parser.error("Target must be an existing directory.")

    print("\nStarting SAST Security Scan...")
    print(f"Target: {target.resolve()}")

    findings = scan_directory(target)

    report = {
        "scanner": "Unified Security Hub - SAST",
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "target": str(target.resolve()),
        "total_vulnerabilities": len(findings),
        "findings": findings
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=4)

    print("\nScan Completed!")
    print(f"Total findings: {len(findings)}")
    print(f"Report saved to: {output_path}")


if __name__ == "__main__":
    main()
