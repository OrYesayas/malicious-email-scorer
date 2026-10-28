"""Deceptive links: the visible text shows one site, but the link leads to another."""
import re
from urllib.parse import urlsplit

from app.analyzers.sender import same_organization
from app.models import EmailPayload, Signal

# Visible text "looks like a site" when it is a single word with dots,
# like "paypal.com", "www.paypal.com" or "https://www.paypal.com/login".
_LOOKS_LIKE_SITE = re.compile(
    r"^(https?://)?[a-z0-9-]+(\.[a-z0-9-]+)+(/\S*)?$", re.IGNORECASE
)

POINTS_PER_LINK = 25
MAX_REPORTED_LINKS = 3


def clean_host(host: str) -> str:
    """Lower-case the site name and drop a leading 'www.'."""
    host = host.lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def site_shown(text: str) -> str:
    """The site name the user sees, or '' if the text is not a site (e.g. 'Click here')."""
    text = text.strip()
    if not _LOOKS_LIKE_SITE.match(text):
        return ""
    if "://" not in text:
        text = "http://" + text
    return clean_host(urlsplit(text).hostname or "")


def site_actual(href: str) -> str:
    """The site name the link really leads to, or '' for non-web links (e.g. mailto:)."""
    try:
        parts = urlsplit(href.strip())
        if parts.scheme.lower() not in ("http", "https"):
            return ""
        # .hostname handles tricks like http://paypal.com@evil.com -> evil.com
        return clean_host(parts.hostname or "")
    except ValueError:
        return ""


class LinksAnalyzer:
    name = "links"

    def analyze(self, email: EmailPayload) -> list[Signal]:
        signals: list[Signal] = []
        seen: set[tuple[str, str]] = set()
        for link in email.links:
            shown = site_shown(link.text)
            if not shown:
                continue  # Nothing to compare against, so we don't guess.
            actual = site_actual(link.href)
            if not actual or same_organization(shown, actual):
                continue
            if (shown, actual) in seen:
                continue  # The same trick repeated is reported once.
            seen.add((shown, actual))
            signals.append(Signal(
                id="links.mismatch", category="Links", points=POINTS_PER_LINK,
                description=f"A link shows {shown} but actually leads to {actual}.",
            ))
            if len(signals) >= MAX_REPORTED_LINKS:
                break
        return signals