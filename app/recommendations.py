from .models import Recommendation


def build_recommendations(protected_prompt: str, findings: list) -> list[Recommendation]:
    has_sensitive_data = bool(findings)
    data_note = "Keep the bracketed placeholders exactly as provided; do not replace them with real values." if has_sensitive_data else "Keep the request limited to the information supplied below."
    return [
        Recommendation(
            id="privacy_first",
            title="Privacy-first rewrite",
            description="Preserves the intent while keeping sensitive values tokenized.",
            prompt=f"Help me complete the request below. Treat bracketed tokens as placeholders and complete only the requested task. {data_note}\n\nRequest:\n{protected_prompt}",
        ),
        Recommendation(
            id="minimal_context",
            title="Minimal context rewrite",
            description="Sends only the minimum context needed for a useful answer.",
            prompt=f"Draft a concise, professional response for this privacy-safe request. Keep personal data, credentials and payment details as placeholders. Use only the context supplied below.\n\n{protected_prompt}",
        ),
    ]
