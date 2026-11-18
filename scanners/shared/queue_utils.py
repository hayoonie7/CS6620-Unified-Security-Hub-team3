
import json
import boto3
import os


def get_sqs_client():
    """
    Create an SQS client using configured AWS credentials.
    """
    region = os.getenv("AWS_REGION", "us-east-1")
    return boto3.client("sqs", region_name=region)


def receive_job(queue_url, wait_time=20):
    """
    Receive one job message from an SQS queue.
    """
    sqs = get_sqs_client()

    response = sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=1,
        WaitTimeSeconds=wait_time,
        VisibilityTimeout=120
    )

    messages = response.get("Messages", [])

    if not messages:
        return None

    message = messages[0]

    return {
        "body": json.loads(message["Body"]),
        "receipt_handle": message["ReceiptHandle"]
    }


def delete_job(queue_url, receipt_handle):
    """
    Delete a successfully processed message from SQS.
    """
    sqs = get_sqs_client()

    sqs.delete_message(
        QueueUrl=queue_url,
        ReceiptHandle=receipt_handle
    )


def send_job_result(queue_url, result):
    """
    Send a scanner job result to an SQS queue.
    """
    sqs = get_sqs_client()

    response = sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(result)
    )

    return response["MessageId"]
