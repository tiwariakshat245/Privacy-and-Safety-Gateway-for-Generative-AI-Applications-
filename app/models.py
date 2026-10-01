from typing import Literal

from pydantic import BaseModel, Field


ProtectionAction = Literal["allow", "mask", "redact", "block"]


class AnalyzeRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=50_000)
    policy_id: str = "balanced"
    user_id: str = "demo-user"
    application_id: str = "demo-app"


class GatewayRequest(AnalyzeRequest):
    review_override: bool = False


class Policy(BaseModel):
    id: str
    name: str
    pii_action: ProtectionAction = "mask"
    injection_action: Literal["allow", "warn", "block"] = "block"
    confidential_keywords: list[str] = Field(default_factory=list)
    allowed_categories: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    category: str
    label: str
    start: int
    end: int
    confidence: float
    action: ProtectionAction
    preview: str


class Recommendation(BaseModel):
    id: str
    title: str
    description: str
    prompt: str


class Analysis(BaseModel):
    request_id: str
    policy_id: str
    risk_level: Literal["low", "medium", "high"]
    decision: Literal["allow", "review", "block"]
    protected_prompt: str
    findings: list[Finding]
    injection_signals: list[str]
    original_prompt_sha256: str
    recommendations: list[Recommendation] = Field(default_factory=list)


class GatewayResponse(BaseModel):
    analysis: Analysis
    upstream: dict | None = None
