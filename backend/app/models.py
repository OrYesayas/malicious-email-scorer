"""Request and response schemas.

Everything that arrives from the add-on originates in an email, so it is
untrusted: every field is bounded and unknown fields are rejected.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Header(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(max_length=100)
    value: str = Field(max_length=2000)


class Link(BaseModel):
    model_config = ConfigDict(extra="forbid")
    href: str = Field(max_length=2048)
    text: str = Field(default="", max_length=300)


class Attachment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(max_length=255)
    content_type: str = Field(default="", max_length=255)
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class EmailPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    headers: list[Header] = Field(default_factory=list, max_length=50)
    sender: str = Field(max_length=500)
    reply_to: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1000)
    body_text: str = Field(default="", max_length=50_000)
    links: list[Link] = Field(default_factory=list, max_length=100)
    attachments: list[Attachment] = Field(default_factory=list, max_length=20)

    def headers_named(self, name: str) -> list[str]:
        """Return header values in their original (top-to-bottom) order."""
        wanted = name.lower()
        return [h.value for h in self.headers if h.name.lower() == wanted]


Verdict = Literal["SAFE", "SUSPICIOUS", "MALICIOUS"]


class Signal(BaseModel):
    id: str
    category: str
    description: str
    points: int = Field(ge=0, le=100)


class AnalysisResult(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    summary: str
    signals: list[Signal]
