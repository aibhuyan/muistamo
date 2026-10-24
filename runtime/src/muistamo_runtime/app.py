from fastapi import FastAPI
from muistamo_contracts.v1.common.healthstatus import HealthStatus, Status

SERVICE = "runtime"

app = FastAPI(title="muistamo-runtime")


@app.get("/healthz")
def healthz() -> HealthStatus:
    return HealthStatus(status=Status.ok, service=SERVICE)
