
import json
import boto3

from datetime import datetime, timezone
from pathlib import Path


def create_report(scanner_name, target, findings):
    """
    Create a standardized JSON security scan report.
    """
    return {
        "scanner": scanner_name,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "total_vulnerabilities": len(findings),
        "findings": findings
    }


def save_report(report, output_path):
    """
    Save the security scan report as a JSON file.
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return str(output_file)


def upload_report_to_s3(report_path, bucket_name, s3_key):
    """
    Upload a JSON security report to an Amazon S3 bucket.
    AWS credentials and region must be configured.
    """
    s3_client = boto3.client("s3")

    s3_client.upload_file(
        str(report_path),
        bucket_name,
        s3_key,
        ExtraArgs={
            "ContentType": "application/json"
        }
    )

    return f"s3://{bucket_name}/{s3_key}"
