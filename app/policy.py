from pathlib import Path
import json

from .models import Policy


DEFAULT_POLICIES = {
    "balanced": Policy(
        id="balanced", name="Balanced protection", pii_action="mask", injection_action="block",
        confidential_keywords=["confidential", "internal only", "do not share"],
    ),
    "strict": Policy(
        id="strict", name="Strict protection", pii_action="block", injection_action="block",
        confidential_keywords=["confidential", "internal only", "do not share", "secret", "private"],
    ),
    "research": Policy(
        id="research", name="Research review", pii_action="redact", injection_action="warn",
        confidential_keywords=["exam answer", "unpublished", "proprietary"],
    ),
}


class PolicyStore:
    def __init__(self, path: str = "policies.json"):
        self.path = Path(path)
        self.policies = dict(DEFAULT_POLICIES)
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.policies.update({p["id"]: Policy.model_validate(p) for p in data})
            except (OSError, ValueError):
                pass

    def save(self):
        self.path.write_text(
            json.dumps([p.model_dump() for p in self.policies.values()], indent=2), encoding="utf-8"
        )

    def get(self, policy_id: str) -> Policy:
        return self.policies.get(policy_id, self.policies["balanced"])

    def all(self) -> list[Policy]:
        return list(self.policies.values())

    def put(self, policy_id: str, policy: Policy) -> Policy:
        policy.id = policy_id
        self.policies[policy_id] = policy
        self.save()
        return policy
