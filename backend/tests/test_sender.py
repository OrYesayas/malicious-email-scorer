from app.analyzers.sender import SenderAnalyzer
from app.models import EmailPayload


def ids(**fields) -> set[str]:
    return {s.id for s in SenderAnalyzer().analyze(EmailPayload(**fields))}


def test_display_name_spoof_detected():
    assert "sender.display_name_spoof" in ids(sender='"support@paypal.com" <x@evil.example>')


def test_reply_to_other_domain_detected():
    assert "sender.reply_to_mismatch" in ids(sender="a@bank.com", reply_to="b@gmail.com")


def test_reply_to_subdomain_is_fine():
    assert ids(sender="a@mail.bank.com", reply_to="b@bank.com") == set()
