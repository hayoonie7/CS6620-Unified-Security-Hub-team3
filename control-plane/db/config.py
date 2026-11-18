"""Shared DynamoDB connection settings.

Locally, DYNAMODB_ENDPOINT points at DynamoDB Local.
On AWS, it connects to the real service using EC2 instance
"""
import os
import boto3

ENDPOINT = os.getenv("DYNAMODB_ENDPOINT", "http://localhost:8000")
REGION = os.getenv("AWS_REGION", "us-east-1")

JOBS_TABLE = os.getenv("JOBS_TABLE", "ush-dev-jobs")
TARGETS_TABLE = os.getenv("TARGETS_TABLE", "ush-dev-approved-targets")


def get_dynamodb():
    if ENDPOINT:
        # DynamoDB Local accepts any credentials, so dummy values are fine.
        return boto3.resource(
            "dynamodb",
            endpoint_url=ENDPOINT,
            region_name=REGION,
            aws_access_key_id="local",
            aws_secret_access_key="local",
        )
    return boto3.resource("dynamodb", region_name=REGION)
