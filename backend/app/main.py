import logging
import os
from contextlib import asynccontextmanager
from functools import lru_cache

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError

from app.analyzers import run_analyzers
from app.models import AnalysisResult, EmailPayload
from app.scoring import score
from app.security import verify_signature

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scorer")

MAX_BODY_BYTES = 512 * 1024


@lru_cache
def get_secret() -> bytes:
    secret = os.environ.get("HMAC_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("HMAC_SECRET must be set and at least 32 characters long")
    return secret.encode()


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_secret()  # Fail fast on startup if the service is misconfigured.
    yield


# Interactive docs are disabled: this is a private API, not a public one.
app = FastAPI(title="Malicious Email Scorer", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


# Note: Cloud Run reserves some paths ending in "z" (like /healthz),
# so the health check uses /health instead.
@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: Request) -> AnalysisResult:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large")
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large")

    if not verify_signature(
        body,
        request.headers.get("x-timestamp", ""),
        request.headers.get("x-signature", ""),
        get_secret(),
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        email = EmailPayload.model_validate_json(body)
    except ValidationError:
        # Don't echo validation details: they would contain email content.
        raise HTTPException(status_code=422, detail="Invalid payload") from None

    result = score(run_analyzers(email))
    logger.info("Analyzed message: score=%d verdict=%s signals=%d",
                result.score, result.verdict, len(result.signals))
    return result
