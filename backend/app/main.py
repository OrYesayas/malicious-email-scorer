import logging
import os
from contextlib import asynccontextmanager
from functools import lru_cache

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.agent import build_agent
from app.analyzers import run_analyzers
from app.models import AnalysisResult, EmailPayload
from app.scoring import score
from app.security import verify_signature

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scorer")

MAX_BODY_BYTES = 512 * 1024

# The AI analyst is optional. It is None unless AI_ENABLED=true is set.
AGENT = build_agent()


@lru_cache
def get_secret() -> bytes:
    """Reads the shared secret from the environment once, and refuses a weak or missing one."""
    secret = os.environ.get("HMAC_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("HMAC_SECRET must be set and at least 32 characters long")
    return secret.encode()


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Runs when the server starts: stops it right away if it is not set up correctly."""
    get_secret()  # Fail fast on startup if the service is misconfigured.
    yield


# Interactive docs are disabled: this is a private API, not a public one.
app = FastAPI(title="Malicious Email Scorer", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


# Note: Cloud Run reserves some paths ending in "z" (like /healthz),
# so the health check uses /health instead.
@app.get("/health")
def health() -> dict:
    """Tells Cloud Run that the server is alive. Open to everyone, because it reveals nothing."""
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: Request) -> AnalysisResult:
    """Checks the request step by step (size, signature, format), then scores the email."""
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

    # 1. Deterministic checks: the base score, which the AI can never lower.
    signals = run_analyzers(email)

    # 2. Optional AI analyst on top. It runs only when the rules already found
    #    something, which saves cost and waiting time on clean emails.
    base_score = score(signals).score
    if AGENT is not None and base_score > 0:
        ai_signal = await run_in_threadpool(AGENT.run_safely, email, signals, base_score)
        if ai_signal is not None:
            signals.append(ai_signal)

    result = score(signals)
    logger.info("Analyzed message: score=%d verdict=%s signals=%d",
                result.score, result.verdict, len(result.signals))
    return result
