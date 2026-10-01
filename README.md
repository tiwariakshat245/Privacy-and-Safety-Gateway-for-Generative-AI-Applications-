# Privacy and Safety Gateway for Generative AI Applications

A small, runnable proof of concept that sits between an application and an AI service. It detects sensitive data and prompt-injection signals, applies a configurable policy, lets a reviewer override the decision, and records an audit trail.

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. The API documentation is at http://127.0.0.1:8000/docs.

## Host it on a public URL

### Render (recommended)

1. Push this repository to GitHub.
2. Create a new **Web Service** at https://render.com and select the repository.
3. Render will use `render.yaml`, install the dependencies, and start the service on its assigned port.
4. Open the generated `https://...onrender.com` URL.

The health check is available at `/api/health`. The included `Dockerfile` also lets you deploy the same app to Railway, Fly.io, a VPS, or any Docker host.

For production model calls, add `AI_API_URL`, `AI_API_KEY`, and `AI_MODEL` as platform environment variables. If they are left unset, the gateway uses its local demo response.

The gateway defaults to a local demo response so the project works without an external model key. To forward allowed prompts to an OpenAI-compatible endpoint, set:

```powershell
$env:AI_API_URL = "https://api.openai.com/v1/chat/completions"
$env:AI_API_KEY = "..."
$env:AI_MODEL = "gpt-4o-mini"
```

## Main API

`POST /api/analyze` analyzes a prompt without sending it upstream.

`POST /api/requests` analyzes a prompt and, when policy permits, sends the protected prompt to the configured model adapter. Use `review_override: true` to approve a blocked request after inspection.

`GET /api/policies` and `PUT /api/policies/{policy_id}` manage policy settings.

`GET /api/audit` returns the local audit trail. Audit entries contain the original prompt only as a one-way hash; the protected prompt is retained for reproducibility.

## Design choices

- PII detection is deliberately explainable and local: email, phone, credit-card-like numbers, API keys, passwords, government-ID-like values, and configurable confidential keywords.
- Detection spans are replaced with stable tokens such as `[EMAIL_1]`. The original value is represented in the audit trail only by a one-way hash.
- Prompt-injection detection flags instruction override language, requests to reveal system prompts, role-play based bypasses, and suspicious tool or secret exfiltration requests.
- Policies are per application/user profile and can choose `allow`, `mask`, `redact`, or `block` for sensitive findings.
- This is a proof of concept, not a universal DLP system. Production use should add a durable database, authentication, secrets management, provider-specific adapters, and a reviewed detection benchmark.
