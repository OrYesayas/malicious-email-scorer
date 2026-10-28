import hashlib
import hmac
import json
import os
import time

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
SECRET = os.environ["HMAC_SECRET"].encode()

GOOGLE_PASS = "mx.google.com; dkim=pass header.i=@bank.com; spf=pass smtp.mailfrom=bank.com; dmarc=pass (p=REJECT) header.from=bank.com"
GOOGLE_FAIL = "mx.google.com; dkim=fail header.i=@bank.com; spf=fail smtp.mailfrom=evil.example; dmarc=fail (p=REJECT) header.from=bank.com"


def signed_post(payload: dict, timestamp: str | None = None):
    body = json.dumps(payload).encode()
    ts = timestamp or str(int(time.time()))
    sig = hmac.new(SECRET, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return client.post("/analyze", content=body, headers={
        "Content-Type": "application/json", "X-Timestamp": ts, "X-Signature": sig,
    })


def email(**overrides) -> dict:
    base = {"sender": "Bank <alerts@bank.com>", "headers": [
        {"name": "authentication-results", "value": GOOGLE_PASS}]}
    base.update(overrides)
    return base


def test_rejects_unsigned_request():
    assert client.post("/analyze", json=email()).status_code == 401


def test_rejects_stale_timestamp():
    assert signed_post(email(), timestamp=str(int(time.time()) - 3600)).status_code == 401


def test_rejects_unknown_fields():
    assert signed_post(email(unexpected="x")).status_code == 422


def test_clean_email_is_safe():
    result = signed_post(email()).json()
    assert result["verdict"] == "SAFE"
    assert result["score"] == 0


def test_failed_authentication_is_malicious():
    result = signed_post(email(headers=[{"name": "authentication-results", "value": GOOGLE_FAIL}])).json()
    assert result["verdict"] == "MALICIOUS"
    ids = {s["id"] for s in result["signals"]}
    assert {"auth.spf_fail", "auth.dkim_fail", "auth.dmarc_fail"} <= ids


def test_forged_auth_header_is_ignored():
    forged = "evil.example; spf=pass dkim=pass dmarc=pass"
    result = signed_post(email(headers=[{"name": "authentication-results", "value": forged}])).json()
    assert "auth.missing" in {s["id"] for s in result["signals"]}


class RecordingAgent:
    """Stands in for the AI analyst and remembers whether it was asked to run."""

    def __init__(self):
        self.calls = 0

    def run_safely(self, email, signals, base_score):
        self.calls += 1
        return None


def test_agent_is_skipped_for_clean_emails(monkeypatch):
    agent = RecordingAgent()
    monkeypatch.setattr("app.main.AGENT", agent)
    signed_post(email())
    assert agent.calls == 0


def test_agent_runs_when_rules_found_something(monkeypatch):
    agent = RecordingAgent()
    monkeypatch.setattr("app.main.AGENT", agent)
    signed_post(email(headers=[{"name": "authentication-results", "value": GOOGLE_FAIL}]))
    assert agent.calls == 1
