import logging

from app.analyzers.authentication import AuthenticationAnalyzer
from app.analyzers.base import Analyzer
from app.analyzers.sender import SenderAnalyzer
from app.models import EmailPayload, Signal

logger = logging.getLogger(__name__)

ANALYZERS: list[Analyzer] = [
    AuthenticationAnalyzer(),
    SenderAnalyzer(),
]


def run_analyzers(email: EmailPayload) -> list[Signal]:
    signals: list[Signal] = []
    for analyzer in ANALYZERS:
        try:
            signals.extend(analyzer.analyze(email))
        except Exception:
            # One broken check must not hide the others, but the user is told
            # the analysis is incomplete. Email content is never logged.
            logger.error("Analyzer %s failed", analyzer.name, exc_info=True)
            signals.append(Signal(
                id=f"{analyzer.name}.error", category="System", points=0,
                description=f"The {analyzer.name} check could not run, so this result may be incomplete.",
            ))
    return signals
