"""SPF / DKIM / DMARC results, read from Gmail's own Authentication-Results header."""
import re

from app.models import EmailPayload, Signal

# Gmail stamps its verdict with this authserv-id. Any other
# Authentication-Results header may have been written by the sender
# to make a spoofed message look verified, so it is ignored.
TRUSTED_AUTHSERV_ID = "mx.google.com"

_MECHANISMS = ("spf", "dkim", "dmarc")
_RESULT_PATTERNS = {m: re.compile(rf"\b{m}=([a-z]+)", re.IGNORECASE) for m in _MECHANISMS}


def parse_auth_results(value: str) -> dict[str, str]:
    results = {}
    for mechanism, pattern in _RESULT_PATTERNS.items():
        match = pattern.search(value)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


def trusted_auth_results(email: EmailPayload) -> dict[str, str] | None:
    for value in email.headers_named("authentication-results"):
        if value.strip().lower().startswith(TRUSTED_AUTHSERV_ID + ";"):
            return parse_auth_results(value)
    return None


class AuthenticationAnalyzer:
    name = "authentication"

    def analyze(self, email: EmailPayload) -> list[Signal]:
        results = trusted_auth_results(email)
        if results is None:
            return [Signal(
                id="auth.missing",
                category="Authentication",
                description="Gmail's authentication verdict was not found, so the sender could not be verified.",
                points=10,
            )]

        signals = []
        spf = results.get("spf")
        if spf == "fail":
            signals.append(Signal(
                id="auth.spf_fail", category="Authentication", points=20,
                description="SPF failed: the sending server is not authorized to send mail for this domain.",
            ))
        elif spf == "softfail":
            signals.append(Signal(
                id="auth.spf_softfail", category="Authentication", points=10,
                description="SPF soft-failed: the sending server is probably not authorized for this domain.",
            ))
        if results.get("dkim") == "fail":
            signals.append(Signal(
                id="auth.dkim_fail", category="Authentication", points=15,
                description="DKIM failed: the message signature is invalid, so it may have been altered or forged.",
            ))
        if results.get("dmarc") == "fail":
            signals.append(Signal(
                id="auth.dmarc_fail", category="Authentication", points=30,
                description="DMARC failed: the domain in the From address did not authorize this message.",
            ))
        return signals
