"""Sender identity tricks: Reply-To redirection and display-name spoofing."""
import re
from email.utils import parseaddr

from app.models import EmailPayload, Signal

_ADDRESS_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def domain_of(address: str) -> str:
    _, addr = parseaddr(address)
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def same_organization(a: str, b: str) -> bool:
    """Treat a domain and its subdomains as the same sender (mail.x.com ~ x.com).

    Known limitation: does not use the Public Suffix List, so unrelated
    domains under a shared registrar are not distinguished by registrable domain.
    """
    return a == b or a.endswith("." + b) or b.endswith("." + a)


class SenderAnalyzer:
    name = "sender"

    def analyze(self, email: EmailPayload) -> list[Signal]:
        signals = []
        display_name, _ = parseaddr(email.sender)
        from_domain = domain_of(email.sender)

        reply_domain = domain_of(email.reply_to) if email.reply_to else ""
        if reply_domain and from_domain and not same_organization(reply_domain, from_domain):
            signals.append(Signal(
                id="sender.reply_to_mismatch", category="Sender", points=15,
                description=f"Replies will go to {reply_domain}, not to the sender's domain {from_domain}.",
            ))

        shown = _ADDRESS_IN_TEXT.search(display_name)
        if shown and from_domain and not same_organization(shown.group(1).lower(), from_domain):
            signals.append(Signal(
                id="sender.display_name_spoof", category="Sender", points=25,
                description=(
                    f"The display name shows an address at {shown.group(1).lower()}, "
                    f"but the message actually comes from {from_domain}."
                ),
            ))
        return signals
