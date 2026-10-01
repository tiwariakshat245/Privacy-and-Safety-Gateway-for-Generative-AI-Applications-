import os

import httpx


async def complete(prompt: str) -> dict:
    api_url = os.getenv("AI_API_URL")
    api_key = os.getenv("AI_API_KEY")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")
    if not api_url or not api_key:
        return {"provider": "local-demo", "model": "gateway-demo", "content": "Demo response: the protected prompt was accepted by the gateway."}
    response = await httpx.AsyncClient(timeout=30).post(
        api_url,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": model, "messages": [{"role": "user", "content": prompt}]},
    )
    response.raise_for_status()
    payload = response.json()
    return {"provider": "openai-compatible", "model": model, "content": payload.get("choices", [{}])[0].get("message", {}).get("content", ""), "raw": payload}
