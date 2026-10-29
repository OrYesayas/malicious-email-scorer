from typing import Protocol

from app.models import EmailPayload, Signal


class Analyzer(Protocol):
    """Each analyzer inspects one aspect of the email and explains what it found."""

    name: str

    def analyze(self, email: EmailPayload) -> list[Signal]:
        """Returns the findings of this check. An empty list means nothing was found."""
        ...
