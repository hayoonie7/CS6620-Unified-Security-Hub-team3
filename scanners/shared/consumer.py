
import os
import sys
import tempfile
import subprocess
import zipfile
from pathlib import Path
from pathlib import PurePosixPath

from queue_utils import receive_job, delete_job, send_job_result
from report_utils import upload_report_to_s3


AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET = os.getenv("S3_BUCKET")
REPORT_PREFIX = os.getenv("REPORT_PREFIX", "reports")

SAST_SCANNER = Path(__file__).resolve().parents[1] / "sast" / "scanner.py"
PENTEST_SCANNER = Path(__file__).resolve().parents[1] / "pentest" / "scanner.py"


def download_input(s3_key, destination):
    import boto3

    s3 = boto3.client("s3", region_name=AWS_REGION)
    s3.download_file(S3_BUCKET, s3_key, str(destination))


def process_job(job):
    job_id = job["job_id"]
    scan_type = job["scan_type"].upper()
    input_key = job["input_key"]

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
                check=True
            )

        elif scan_type == "PENTEST":
            target_file = temp_path / "target.txt"
            download_input(input_key, target_file)

            target_url = target_file.read_text(
                encoding="utf-8"
            ).strip()

            subprocess.run(
                [
                    sys.executable,
                    str(PENTEST_SCANNER),
                    "--target",
                    target_url,
                    "--output",
                    str(report_path)
                ],
                check=True
            )

        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")

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

    print(f"Starting {scan_type} consumer...", flush=True)

    while True:
        message = receive_job(input_queue_url)

        if message is None:
            continue

        job = message["body"]
        receipt_handle = message["receipt_handle"]

        try:
            if job.get("scan_type", "").upper() != scan_type:
                raise ValueError(
                    "Message scan_type does not match this consumer."
                )

            result = process_job(job)

        except Exception as error:
            print(
                f"Job {job.get('job_id')} failed: {error}",
                flush=True
            )

            # Do not delete failed messages.
            # SQS will make them visible again after the visibility timeout.
            continue

        try:
            send_job_result(result_queue_url, result)

            # Delete only after successful processing and result publication.
            delete_job(input_queue_url, receipt_handle)

            print(
                f"Job {job['job_id']} completed successfully.",
                flush=True
            )

        except Exception as error:
            # Keep the original message for retry.
            print(
                f"Could not publish result or delete message: {error}",
                flush=True
            )
            

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

            target = (destination / Path(*member_path.parts)).resolve()

            if target != destination and destination not in target.parents:
                raise ValueError("ZIP entry escapes the extraction directory.")

            # Reject symbolic links.
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Symbolic links are not allowed in ZIP files.")

        archive.extractall(destination)



if __name__ == "__main__":
    run_consumer()
