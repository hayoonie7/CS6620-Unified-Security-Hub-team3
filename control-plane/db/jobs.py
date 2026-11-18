"""Read and write job records. The API imports these functions,
so no other code needs to know DynamoDB details.
"""
import uuid
from datetime import datetime, timezone

from boto3.dynamodb.conditions import Key

from db.config import get_dynamodb, JOBS_TABLE, TARGETS_TABLE

_table = get_dynamodb().Table(JOBS_TABLE)
_targets = get_dynamodb().Table(TARGETS_TABLE)

VALID_STATUSES = {"QUEUED", "RUNNING", "SUCCEEDED", "FAILED"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def create_job(user_id, project_id, scan_type, target=None, input_key=None):
    now = _now()
    job = {
        "job_id": uuid.uuid4().hex,
        "user_id": user_id,
        "project_id": project_id,
        "scan_type": scan_type,          # "SAST" or "PENTEST"
        "status": "QUEUED",
        "created_at": now,
        "updated_at": now,
    }
    if target:
        job["target"] = target           # pentest URL
    if input_key:
        job["input_key"] = input_key     # S3 key of uploaded code
    _table.put_item(Item=job)
    return job


def get_job(job_id):
    return _table.get_item(Key={"job_id": job_id}).get("Item")


def update_status(job_id, status, report_key=None, error_message=None):
    if status not in VALID_STATUSES:
        raise ValueError(f"Unknown status: {status}")

    # "status" is a DynamoDB reserved word, so it needs a placeholder (#s).
    expr = "SET #s = :s, updated_at = :u"
    values = {":s": status, ":u": _now()}
    if report_key:
        expr += ", report_key = :r"
        values[":r"] = report_key
    if error_message:
        expr += ", error_message = :e"
        values[":e"] = error_message

    _table.update_item(
        Key={"job_id": job_id},
        UpdateExpression=expr,
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues=values,
        # Refuse to create a new item if the job_id doesn't exist.
        ConditionExpression="attribute_exists(job_id)",
    )


def list_jobs_for_user(user_id, limit=20):
    resp = _table.query(
        IndexName="by-user",
        KeyConditionExpression=Key("user_id").eq(user_id),
        ScanIndexForward=False,          # newest first
        Limit=limit,
    )
    return resp["Items"]


def list_jobs_for_project(project_id, limit=20):
    resp = _table.query(
        IndexName="by-project",
        KeyConditionExpression=Key("project_id").eq(project_id),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp["Items"]


def add_approved_target(host, approved_by):
    _targets.put_item(Item={"host": host, "approved_by": approved_by,
                            "approved_at": _now()})


def is_approved_target(host):
    return "Item" in _targets.get_item(Key={"host": host})
