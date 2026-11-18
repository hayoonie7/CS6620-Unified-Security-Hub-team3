"""Quick end-to-end check of the table design.

Run (after create_tables):  python -m db.try_it
"""
from db import jobs

jobs.add_approved_target("staging.payments.internal", approved_by="ha.kim")
print("Approved target?", jobs.is_approved_target("staging.payments.internal"))
print("Random target?  ", jobs.is_approved_target("example.com"))

a = jobs.create_job("ha.kim", "payments-api", "SAST",
                    input_key="uploads/demo/source.zip")
b = jobs.create_job("ha.kim", "payments-api", "PENTEST",
                    target="https://staging.payments.internal")
c = jobs.create_job("sai.v", "auth-service", "SAST",
                    input_key="uploads/demo2/source.zip")

jobs.update_status(a["job_id"], "RUNNING")
jobs.update_status(a["job_id"], "SUCCEEDED",
                   report_key=f"reports/sast/{a['job_id']}.json")
jobs.update_status(b["job_id"], "FAILED", error_message="Target timed out")

print("\n1) Get status for one job:")
print("  ", jobs.get_job(a["job_id"])["status"])

print("\n2) List ha.kim's scans (newest first):")
for j in jobs.list_jobs_for_user("ha.kim"):
    print("  ", j["scan_type"], j["status"], j["created_at"])

print("\n3) Scan history for payments-api:")
for j in jobs.list_jobs_for_project("payments-api"):
    print("  ", j["scan_type"], j["status"])
