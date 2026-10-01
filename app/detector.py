import hashlib
import re
from dataclasses import dataclass

from .models import Finding, Policy


@dataclass(frozen=True)
class Rule:
    category: str
    label: str
    pattern: re.Pattern[str]
    confidence: float


RULES = [
    Rule("email", "Email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), .99),
    Rule("credit_card", "Payment card number", re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"), .93),
    Rule("phone", "Phone number", re.compile(r"(?<!\d)(?:\+?\d[\d ()-]{8,}\d)(?!\d)"), .90),
    Rule("api_key", "API key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})\b"), .98),
    Rule("password", "Password or secret", re.compile(r"(?i)\b(?:password|passwd|secret|token)\s*[:=]\s*[^\s,;]+"), .96),
    Rule("government_id", "Government ID-like value", re.compile(r"\b(?:SSN|PAN|Aadhaar|passport)\s*[:#-]?\s*[A-Z0-9 -]{6,}\b", re.I), .86),
    Rule("home_address", "Home address", re.compile(r"\b(?:address\s+(?:at|is)\s+)?\d{1,6}\s+[A-Z0-9][A-Za-z0-9 .'-]{2,60}\s+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Terrace|Trail|Way)\b(?:,\s*[A-Za-z .'-]+)?", re.I), .88),
]

INJECTION_RULES = [
    ("instruction_override", re.compile(r"(?i)\b(ignore|disregard|forget|override)\b.{0,80}\b(previous|prior|system|developer|instructions?)\b")),
    ("system_prompt_exfiltration", re.compile(r"(?i)\b(reveal|show|print|repeat|leak|dump)\b.{0,80}\b(system prompt|hidden prompt|developer message|instructions?)\b")),
    ("role_bypass", re.compile(r"(?i)\b(pretend|roleplay|act as|you are now)\b.{0,80}\b(no rules|unrestricted|jailbreak|DAN|bypass)\b")),
    ("secret_exfiltration", re.compile(r"(?i)\b(send|upload|post|exfiltrate|copy)\b.{0,80}\b(secret|credential|key|private data|environment variable)\b")),
    ("tool_abuse", re.compile(r"(?i)\b(run|execute|call)\b.{0,60}\b(shell|terminal|browser|tool|function)\b.{0,80}\b(without|ignore|approval)\b")),
]


def _preview(value: str) -> str:
    if len(value) <= 4:
        return "•" * len(value)
    return value[:2] + "•" * max(2, len(value) - 4) + value[-2:]


def analyze_prompt(prompt: str, policy: Policy, request_id: str) -> tuple[list[Finding], list[str], str, str, str, str]:
    findings: list[Finding] = []
    replacements: list[tuple[int, int, str]] = []
    counter: dict[str, int] = {}

    for rule in RULES:
        for match in rule.pattern.finditer(prompt):
            if any(match.start() < end and match.end() > start for start, end, _ in replacements):
                continue
            counter[rule.category] = counter.get(rule.category, 0) + 1
            action = policy.pii_action
            token = f"[{rule.category.upper()}_{counter[rule.category]}]"
            findings.append(Finding(category=rule.category, label=rule.label, start=match.start(), end=match.end(), confidence=rule.confidence, action=action, preview=_preview(match.group())))
            replacements.append((match.start(), match.end(), token if action == "mask" else "[REDACTED]"))

    lower_prompt = prompt.lower()
    for keyword in policy.confidential_keywords:
        start = lower_prompt.find(keyword.lower())
        while start >= 0:
            end = start + len(keyword)
            if not any(start < e and end > s for s, e, _ in replacements):
                findings.append(Finding(category="confidential_keyword", label="Confidential keyword", start=start, end=end, confidence=.82, action=policy.pii_action, preview=keyword[:2] + "•" * max(1, len(keyword) - 2)))
                replacements.append((start, end, "[CONFIDENTIAL]" if policy.pii_action != "mask" else "[CONFIDENTIAL_1]"))
            start = lower_prompt.find(keyword.lower(), end)

    injection_signals = [name for name, pattern in INJECTION_RULES if pattern.search(prompt)]
    protected = prompt
    for start, end, replacement in sorted(replacements, reverse=True):
        protected = protected[:start] + replacement + protected[end:]
    decision = "allow"
    if injection_signals and policy.injection_action == "block":
        decision = "block"
    elif findings and policy.pii_action == "block":
        decision = "block"
    elif injection_signals or findings:
        decision = "review"
    risk = "high" if decision == "block" or injection_signals else "medium" if findings else "low"
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    return findings, injection_signals, protected, digest, decision, risk
