"""Turns individual signals into one explainable score and verdict."""
from app.models import AnalysisResult, Signal

SUSPICIOUS_THRESHOLD = 25
MALICIOUS_THRESHOLD = 60

_SUMMARIES = {
    "SAFE": "No strong warning signs were found in this email.",
    "SUSPICIOUS": "Some warning signs were found. Be careful with links, attachments and requests in this email.",
    "MALICIOUS": "Several strong warning signs were found. Do not click links, open attachments or reply.",
}


def score(signals: list[Signal]) -> AnalysisResult:
    total = min(100, sum(s.points for s in signals))
    if total >= MALICIOUS_THRESHOLD:
        verdict = "MALICIOUS"
    elif total >= SUSPICIOUS_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    ordered = sorted(signals, key=lambda s: s.points, reverse=True)
    return AnalysisResult(score=total, verdict=verdict, summary=_SUMMARIES[verdict], signals=ordered)
