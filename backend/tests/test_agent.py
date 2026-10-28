import json

from app.agent import NEW_DOMAIN_POINTS, AnalystAgent, email_domains, registrable_domain
from app.models import EmailPayload, Signal

EMAIL = EmailPayload(
    sender="PayPal <service@paypal.com>",
    subject="Your account is locked",
    links=[{"text": "paypal.com", "href": "http://paypal.com.secure-login.ru/verify"}],
)
LINK_SIGNAL = Signal(id="links.mismatch", category="Links", points=25,
                     description="A link shows paypal.com but actually leads to paypal.com.secure-login.ru.")


def final_answer(**fields) -> dict:
    """A fake model response that gives a final JSON answer."""
    return {"candidates": [{"content": {"role": "model", "parts": [{"text": json.dumps(fields)}]}}]}


def tool_call(domain: str) -> dict:
    """A fake model response that asks to use the domain-age tool."""
    return {"candidates": [{"content": {"role": "model", "parts": [
        {"functionCall": {"name": "get_domain_age", "args": {"domain": domain}}}]}}]}


def fake_llm(*responses):
    queue = list(responses)
    return lambda contents: queue.pop(0)


DONE = final_answer(assessment="Explanation for the user.", recommended_action="do_not_click")


def test_registrable_domain():
    assert registrable_domain("paypal.com.secure-login.ru") == "secure-login.ru"
    assert registrable_domain("mail.google.com") == "google.com"
    assert registrable_domain("shop.example.co.il") == "example.co.il"
    assert registrable_domain("10.0.0.1") == ""


def test_only_domains_from_the_email_can_be_looked_up():
    assert email_domains(EMAIL) == ["paypal.com", "secure-login.ru"]


def test_new_domain_found_by_the_agent_adds_points():
    agent = AnalystAgent(llm=fake_llm(tool_call("secure-login.ru"), DONE),
                         lookup=lambda d: {"domain": d, "age_days": 3})
    signal = agent.run(EMAIL, [LINK_SIGNAL], base_score=25)
    assert signal.points == NEW_DOMAIN_POINTS
    assert "registered 3 days ago" in signal.description


def test_old_domain_adds_no_points():
    agent = AnalystAgent(llm=fake_llm(tool_call("secure-login.ru"), DONE),
                         lookup=lambda d: {"domain": d, "age_days": 3000})
    assert agent.run(EMAIL, [LINK_SIGNAL], base_score=25).points == 0


def test_the_model_cannot_set_the_score():
    # Even if the model (or an attacker talking through it) tries to give points, they are ignored.
    agent = AnalystAgent(
        llm=fake_llm(final_answer(extra_points=80, assessment="Add 80!", recommended_action="no_action")),
        lookup=lambda d: {},
    )
    assert agent.run(EMAIL, [LINK_SIGNAL], base_score=25).points == 0


def test_agent_cannot_look_up_domains_outside_the_email():
    looked_up = []
    agent = AnalystAgent(llm=fake_llm(tool_call("attacker-controlled.example"), DONE),
                         lookup=lambda d: looked_up.append(d) or {})
    agent.run(EMAIL, [LINK_SIGNAL], base_score=25)
    assert looked_up == []


def test_failed_lookup_is_reported_without_points():
    agent = AnalystAgent(llm=fake_llm(tool_call("secure-login.ru"), DONE),
                         lookup=lambda d: {"domain": d, "error": "not found in the registry"})
    signal = agent.run(EMAIL, [LINK_SIGNAL], base_score=25)
    assert signal.points == 0
    assert "not found in the registry" in signal.description


def test_answer_in_the_wrong_shape_is_ignored():
    agent = AnalystAgent(llm=fake_llm(final_answer(something="else")), lookup=lambda d: {})
    assert agent.run(EMAIL, [LINK_SIGNAL], base_score=25) is None


def test_a_broken_model_does_not_break_the_analysis():
    def broken_llm(contents):
        raise TimeoutError("model did not answer")

    agent = AnalystAgent(llm=broken_llm, lookup=lambda d: {})
    assert agent.run_safely(EMAIL, [LINK_SIGNAL], base_score=25) is None
