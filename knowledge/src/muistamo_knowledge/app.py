from fastapi import FastAPI
from muistamo_contracts.v1.common.healthstatus import HealthStatus, Status

SERVICE = "knowledge"

app = FastAPI(title="muistamo-knowledge")


@app.get("/healthz")
def healthz() -> HealthStatus:
    return HealthStatus(status=Status.ok, service=SERVICE)
