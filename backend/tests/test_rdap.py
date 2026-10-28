"""Tests for the domain-age tool, using a fake network so no real registry is contacted."""
from datetime import datetime, timedelta, timezone

import httpx

from app.agent import rdap_domain_age

BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.example-registry.com/v1/"]]]}


def fake_http(domain_status: int, registered_days_ago: int = 3) -> httpx.Client:
    registered = (datetime.now(timezone.utc) - timedelta(days=registered_days_ago)).isoformat()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "data.iana.org":
            return httpx.Response(200, json=BOOTSTRAP)
        body = {"events": [{"eventAction": "registration", "eventDate": registered}]}
        return httpx.Response(domain_status, json=body if domain_status == 200 else {})

    return httpx.Client(transport=httpx.MockTransport(handler))


def lookup(domain, http):
    # A fresh cache for every test, so tests do not affect each other.
    from app import agent
    agent._REGISTRY_LIST.clear()
    return rdap_domain_age(domain, http)


def test_age_of_a_registered_domain():
    assert lookup("example.com", fake_http(200, registered_days_ago=3))["age_days"] == 3


def test_unregistered_domain_is_reported_as_such():
    assert lookup("example.com", fake_http(404))["error"] == "this domain is not registered"


def test_blocked_lookup_is_not_reported_as_not_found():
    # This is the real bug we hit: a 403 used to be reported as "not found".
    assert lookup("example.com", fake_http(403))["error"] == "registry lookup failed (HTTP 403)"


def test_domain_ending_without_a_registry():
    assert "does not offer lookups" in lookup("example.zz", fake_http(200))["error"]
