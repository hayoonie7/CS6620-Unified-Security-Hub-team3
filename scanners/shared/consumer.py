
import os
import sys
import json
import tempfile
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

from queue_utils import receive_job, delete_job, send_job_result
from report_utils import upload_report_to_s3


AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET = os.getenv("S3_BUCKET")
REPORT_PREFIX = os.getenv("REPORT_PREFIX", "reports")

SAST_SCANNER = Path(__file__).resolve().parents[1] / "sast" / "scanner.py"
PENTEST_SCANNER = Path(__file__).resolve().parents[1] / "pentest" / "scanner.py"


def validate_job(job):
    if not isinstance(job, dict):
        raise ValueError("Job must be a JSON object.")

    job_id = job.get("job_id")
    scan_type = job.get("scan_type", "")
    input_key = job.get("input_key")

    if not isinstance(job_id, str) or not job_id.strip():
        raise ValueError("Missing or invalid job_id.")

    if not isinstance(scan_type, str):
        raise ValueError("Invalid scan_type.")

    scan_type = scan_type.upper().strip()

    if scan_type not in ("SAST", "PENTEST"):
        raise ValueError(f"Unsupported scan type: {scan_type}")

    if not isinstance(input_key, str) or not input_key.strip():
        raise ValueError("Missing or invalid input_key.")

    return job_id.strip(), scan_type, input_key.strip()


def download_input(s3_key, destination):
    import boto3

    if not S3_BUCKET:
        raise ValueError("S3_BUCKET is not configured.")

    s3 = boto3.client("s3", region_name=AWS_REGION)
    s3.download_file(S3_BUCKET, s3_key, str(destination))


def safe_extract_zip(zip_path, destination):
    destination = Path(destination).resolve()

    max_files = 1000
    max_uncompressed_size = 100 * 1024 * 1024

    with zipfile.ZipFile(zip_path, "r") as archive:
        members = archive.infolist()

        if len(members) > max_files:
            raise ValueError("ZIP contains too many files.")

        total_size = sum(member.file_size for member in members)

        if total_size > max_uncompressed_size:
            raise ValueError("ZIP exceeds the allowed uncompressed size.")

        for member in members:
            member_path = PurePosixPath(member.filename)

            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError("Unsafe path detected in ZIP.")

            target = (
                destination / Path(*member_path.parts)
            ).resolve()

            if target != destination and destination not in target.parents:
                raise ValueError(
                    "ZIP entry escapes the extraction directory."
                )

            # Reject symbolic links.
            file_type = (member.external_attr >> 16) & 0o170000

            if file_type == 0o120000:
                raise ValueError(
                    "Symbolic links are not allowed in ZIP files."
                )

        archive.extractall(destination)


def process_job(job):
    job_id, scan_type, input_key = validate_job(job)

    if not S3_BUCKET:
        raise ValueError("S3_BUCKET is not configured.")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        report_path = temp_path / "report.json"

        if scan_type == "SAST":
            source_zip = temp_path / "source.zip"
            target_dir = temp_path / "source"
            target_dir.mkdir()

            download_input(input_key, source_zip)
            safe_extract_zip(source_zip, target_dir)

            subprocess.run(
                [
                    sys.executable,
                    str(SAST_SCANNER),
                    "--target",
                    str(target_dir),
                    "--output",
                    str(report_path)
                ],
                check=True,
                timeout=600
            )

        elif scan_type == "PENTEST":
            target_file = temp_path / "target.txt"

            download_input(input_key, target_file)

            target_url = target_file.read_text(
                encoding="utf-8"
            ).strip()

            if not target_url:
                raise ValueError("Pentest target URL is empty.")

            subprocess.run(
                [
                    sys.executable,
                    str(PENTEST_SCANNER),
                    "--target",
                    target_url,
                    "--output",
                    str(report_path)
                ],
                check=True,
                timeout=600
            )

        if not report_path.exists():
            raise RuntimeError("Scanner did not generate a report.")

        report_key = f"{REPORT_PREFIX}/{job_id}.json"

        upload_report_to_s3(
            report_path,
            S3_BUCKET,
            report_key
        )

        return {
            "job_id": job_id,
            "scan_type": scan_type,
            "status": "SUCCEEDED",
            "report_key": report_key,
            "error_message": None
        }


def run_consumer():
    scan_type = os.getenv("SCAN_TYPE", "").upper()
    input_queue_url = os.getenv("INPUT_QUEUE_URL")
    result_queue_url = os.getenv("RESULT_QUEUE_URL")

    if scan_type not in ("SAST", "PENTEST"):
        raise ValueError("SCAN_TYPE must be SAST or PENTEST.")

    if not input_queue_url or not result_queue_url:
        raise ValueError("SQS queue URLs must be configured.")

    if not S3_BUCKET:
        raise ValueError("S3_BUCKET is not configured.")

    print(f"Starting {scan_type} consumer...", flush=True)

    while True:
        message = receive_job(input_queue_url)

        if message is None:
            continue

        job = message["body"]
        receipt_handle = message["receipt_handle"]

        job_id = job.get("job_id") if isinstance(job, dict) else None

        try:
            validated_job_id, job_scan_type, _ = validate_job(job)

            if job_scan_type != scan_type:
                raise ValueError(
                    "Message scan_type does not match this consumer."
                )

            result = process_job(job)

        except Exception as error:
            print(
                f"Job {job_id} failed: {error}",
                flush=True
            )

            result = {
                "job_id": job_id,
                "scan_type": scan_type,
                "status": "FAILED",
                "report_key": None,
                "error_message": str(error)[:1000]
            }

        try:
            send_job_result(result_queue_url, result)

            delete_job(input_queue_url, receipt_handle)

            print(
                f"Job {result['job_id']} result published: "
                f"{result['status']}",
                flush=True
            )

        except Exception as error:
            print(
                f"Could not publish result or delete message: {error}",
                flush=True
            )

            # Keep the original message for SQS redelivery.


if __name__ == "__main__":
    run_consumer()
