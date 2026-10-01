from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Lock


class AuditLog:
    def __init__(self, path: str = "audit.jsonl"):
        self.path = Path(path)
        self.lock = Lock()

    def write(self, entry: dict):
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), **entry}
        with self.lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, separators=(",", ":")) + "\n")

    def read(self, limit: int = 100) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        return [json.loads(line) for line in reversed(lines)]
