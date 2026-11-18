"""Creates the jobs table (with two indexes) and the approved-targets table.

Run:  python -m db.create_tables
Safe to run more than once; existing tables are skipped.
"""
from db.config import get_dynamodb, JOBS_TABLE, TARGETS_TABLE


def create_jobs_table(dynamodb):
    dynamodb.create_table(
        TableName=JOBS_TABLE,
        BillingMode="PAY_PER_REQUEST",
        # Only key attributes are declared; other fields are added freely.
        AttributeDefinitions=[
            {"AttributeName": "job_id", "AttributeType": "S"},
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "project_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
        # Access pattern 1: get status for job X
        KeySchema=[{"AttributeName": "job_id", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[
            {   # Access pattern 2: list my scans, newest first
                "IndexName": "by-user",
                "KeySchema": [
                    {"AttributeName": "user_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {   # Access pattern 3: scan history for a project
                "IndexName": "by-project",
                "KeySchema": [
                    {"AttributeName": "project_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def create_targets_table(dynamodb):
    dynamodb.create_table(
        TableName=TARGETS_TABLE,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "host", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "host", "KeyType": "HASH"}],
    )


def main():
    dynamodb = get_dynamodb()
    existing = {t.name for t in dynamodb.tables.all()}

    for name, creator in [(JOBS_TABLE, create_jobs_table),
                          (TARGETS_TABLE, create_targets_table)]:
        if name in existing:
            print(f"{name}: already exists, skipping")
            continue
        creator(dynamodb)
        dynamodb.Table(name).wait_until_exists()
        print(f"{name}: created")


if __name__ == "__main__":
    main()
