# Unified Security Hub – Data Plane Technical Handoff

**Owner:** Sai Swetha Vemulapalli  
**Component:** Data Plane – SAST and Pentest Scanners  
**Project:** CS6620 – Unified Security Hub

## 1. Overview

The Data Plane is responsible for executing security scans, processing jobs received from Amazon SQS, and storing scan reports in Amazon S3.

It contains two independent scanner types:

- **SAST Scanner:** Performs static security checks on uploaded Python source code.
- **Pentest Scanner:** Performs basic, non-destructive HTTP security configuration checks against authorized API endpoints.

Both scanners are packaged as separate Docker images and are designed to run as independent AWS ECS Fargate tasks.

## 2. Project Directory Structure

```text
scanners/
│
├── sast/
│   ├── scanner.py
│   ├── Dockerfile
│   └── test_samples/
│       └── vulnerable_app.py
│
├── pentest/
│   ├── scanner.py
│   ├── Dockerfile
│   └── test_samples/
│
└── shared/
    ├── consumer.py
    ├── queue_utils.py
    ├── report_utils.py
    ├── requirements.txt
    └── README.md
```

## 3. SAST Scanner

The SAST scanner performs static analysis of Python source files using pattern-based security rules.

Current detection rules include:

- Hardcoded passwords
- Hardcoded API keys
- Use of eval()
- Use of exec()
- Dangerous shell execution
- Potential SQL injection

**Local test result:** 6 findings detected in the intentionally vulnerable test application.

### Run locally

```bash
python scanners/sast/scanner.py --target scanners/sast/test_samples
```

### Build Docker image

```bash
docker build -t unified-security-hub-sast:latest -f scanners/sast/Dockerfile .
```

## 4. Pentest Scanner

The Pentest scanner performs basic, non-destructive HTTP security checks against authorized API endpoints.

Current checks include:

- Missing Strict-Transport-Security header
- Missing Content-Security-Policy header
- Missing X-Content-Type-Options header
- Missing X-Frame-Options header
- Insecure HTTP
- TRACE method advertised

**Local test result:** 3 findings detected against the test endpoint.

### Run locally

```bash
python scanners/pentest/scanner.py --target https://httpbin.org/get
```

### Build Docker image

```bash
docker build -t unified-security-hub-pentest:latest -f scanners/pentest/Dockerfile .
```

## 5. SQS Message Contract

The following format was proposed and approved for integration with the API/control plane.

### Input message: API → SQS → Scanner

```json
{
  "job_id": "job-001",
  "scan_type": "SAST",
  "input_key": "inputs/job-001"
}
```

For Pentest jobs, `scan_type` is `PENTEST`.

The `input_key` identifies the input object stored in S3.

### Output message: Scanner → Results SQS Queue

```json
{
  "job_id": "job-001",
  "scan_type": "SAST",
  "status": "SUCCEEDED",
  "report_key": "reports/job-001.json",
  "error_message": null
}
```

For failed jobs, the status will be `FAILED` with an appropriate error message.

## 6. S3 Input and Output Format

### SAST input

- Input format: ZIP archive containing Python source files.
- Storage location: S3 inputs prefix.
- The consumer downloads and safely extracts the archive before scanning.

### Pentest input

- Input format: Text file containing the authorized target URL.
- Storage location: S3 inputs prefix.
- The consumer downloads the file and passes the URL to the Pentest scanner.

### Scan reports

Both scanners generate JSON reports.

Reports are uploaded to the S3 reports prefix.

Proposed object key:

```text
reports/<job_id>.json
```

## 7. Shared Components

### report_utils.py

Provides:

- `create_report()` – Creates a standardized JSON report.
- `save_report()` – Saves a report locally.
- `upload_report_to_s3()` – Uploads a JSON report to Amazon S3.

### queue_utils.py

Provides:

- `get_sqs_client()` – Creates an SQS client.
- `receive_job()` – Receives a job message.
- `delete_job()` – Deletes a successfully processed message.
- `send_job_result()` – Publishes the scanner result.

### consumer.py

The shared consumer:

1. Receives jobs from SQS.
2. Checks the scan type.
3. Downloads input files from S3.
4. Executes the appropriate scanner.
5. Uploads the generated report to S3.
6. Publishes the result to the results queue.
7. Deletes the original SQS message after successful processing and result publication.

Failed processing messages are not deleted, allowing SQS redelivery after the visibility timeout.

## 8. Required Environment Variables

| Variable | Purpose |
|---|---|
| `AWS_REGION` | AWS region, default us-east-1 |
| `SCAN_TYPE` | SAST or PENTEST |
| `S3_BUCKET` | S3 bucket for inputs and reports |
| `INPUT_QUEUE_URL` | Scanner input SQS queue |
| `RESULT_QUEUE_URL` | Results SQS queue |
| `REPORT_PREFIX` | Report prefix, default reports |

AWS credentials should be provided through the ECS task IAM role rather than hardcoded in the container.

## 9. Docker Container Configuration

Both Docker images contain the shared consumer and both scanner implementations.

The scanner type is selected through the `SCAN_TYPE` environment variable.

**SAST task:**

```text
SCAN_TYPE=SAST
```

**Pentest task:**

```text
SCAN_TYPE=PENTEST
```

Container entry point:

```bash
python /app/shared/consumer.py
```

## 10. Current Testing Status

| Component | Status |
|---|---|
| SAST Python scanner | Tested |
| SAST Docker image | Built and tested |
| Pentest Python scanner | Tested |
| Pentest Docker image | Built and tested |
| Shared report utility | Import test passed |
| SQS helper functions | Import test passed |
| Shared consumer | Syntax checked |
| Secure ZIP extraction | Import tested |
| AWS S3 integration | Pending |
| AWS SQS integration | Pending |
| DynamoDB idempotency | Pending |
| ECS Fargate deployment | Pending |

## 11. Pending Work

The following work depends on the infrastructure implementation and team coordination:

1. Finalize SQS queues for SAST, Pentest, and job results.
2. Configure SQS visibility timeout and Dead Letter Queues.
3. Finalize S3 bucket and input/report prefixes.
4. Confirm DynamoDB table name and partition key with the infrastructure team.
5. Implement idempotency to prevent duplicate job execution.
6. Improve duplicate result handling and failure reporting.
7. Push Docker images to Amazon ECR.
8. Configure ECS Fargate task definitions.
9. Configure IAM permissions for S3, SQS, and DynamoDB.
10. Test complete end-to-end job execution.

## 12. Important Implementation Notes

- The SAST scanner currently uses regular-expression-based detection and is a prototype, not a comprehensive static analysis engine.
- Pentest checks are basic configuration checks, not a full penetration-testing framework.
- The shared report utility exists, but the individual scanner scripts still generate their own report structures.
- Failed SQS jobs currently rely on message redelivery. A failure result is not yet published by the consumer.
- Idempotency and duplicate result protection are not yet implemented.
- ZIP extraction includes path traversal, file-count, and uncompressed-size checks; further hardening is required before production use.
- AWS integration has not yet been tested because the infrastructure is still being developed.

---

**Data Plane implementation owner:** Sai Swetha Vemulapalli

**Integration coordination:** Ha Yoon Kim – API/Control Plane; Siddarth Chalasani – Infrastructure/Cloud Platform.
