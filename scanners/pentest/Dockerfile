
FROM python:3.12-slim

WORKDIR /app

COPY scanners/sast/scanner.py /app/sast/scanner.py
COPY scanners/pentest/scanner.py /app/pentest/scanner.py
COPY scanners/shared/ /app/shared/

ENV PYTHONPATH=/app/shared

RUN pip install --no-cache-dir boto3 requests

CMD ["python", "/app/shared/consumer.py"]
