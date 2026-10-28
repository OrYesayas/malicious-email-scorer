from app.analyzers.links import LinksAnalyzer
from app.models import EmailPayload


def ids(text: str, href: str) -> set[str]:
    """Runs the links check on an email with one link, and returns the signal ids."""
    email = EmailPayload(sender="a@bank.com", links=[{"text": text, "href": href}])
    return {s.id for s in LinksAnalyzer().analyze(email)}


def test_lookalike_domain_is_flagged():
    assert "links.mismatch" in ids("amazon.com", "http://amaz0n-support.com")


def test_same_site_different_page_is_fine():
    assert ids("www.leumi.co.il", "https://www.leumi.co.il/login") == set()


def test_click_here_is_ignored():
    assert ids("Click here", "https://bit.ly/3xYz") == set()


def test_brand_as_subdomain_is_flagged():
    assert "links.mismatch" in ids("paypal.com", "http://paypal.com.secure-login.ru/verify")