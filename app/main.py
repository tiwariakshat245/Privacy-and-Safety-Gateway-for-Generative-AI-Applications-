from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .audit import AuditLog
from .detector import analyze_prompt
from .models import Analysis, AnalyzeRequest, GatewayRequest, GatewayResponse, Policy
from .policy import PolicyStore
from .recommendations import build_recommendations
from .upstream import complete

app = FastAPI(title="Privacy and Safety Gateway", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
store = PolicyStore()
audit = AuditLog()
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
app.mount("/assets", StaticFiles(directory=Path(__file__).parent / "static" / "assets"), name="assets")


@app.get("/styles.css")
async def styles():
    return FileResponse(Path(__file__).parent / "static" / "styles.css", media_type="text/css")


@app.get("/app.js")
async def scripts():
    return FileResponse(Path(__file__).parent / "static" / "app.js", media_type="application/javascript")


@app.get("/recommendations.css")
async def recommendations_styles():
    return FileResponse(Path(__file__).parent / "static" / "recommendations.css", media_type="text/css")


@app.get("/slideshow.css")
async def slideshow_styles():
    return FileResponse(Path(__file__).parent / "static" / "slideshow.css", media_type="text/css")


@app.get("/", response_class=HTMLResponse)
async def home():
    return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "sentinel-gateway"}


def make_analysis(request: AnalyzeRequest) -> Analysis:
    policy = store.get(request.policy_id)
    request_id = str(uuid4())
    findings, signals, protected, digest, decision, risk = analyze_prompt(request.prompt, policy, request_id)
    return Analysis(request_id=request_id, policy_id=policy.id, risk_level=risk, decision=decision, protected_prompt=protected, findings=findings, injection_signals=signals, original_prompt_sha256=digest, recommendations=build_recommendations(protected, findings))


@app.post("/api/analyze", response_model=Analysis)
async def analyze(request: AnalyzeRequest):
    result = make_analysis(request)
    audit.write({"request_id": result.request_id, "event": "analyze", "application_id": request.application_id, "user_id": request.user_id, "policy_id": result.policy_id, "decision": result.decision, "risk_level": result.risk_level, "finding_categories": sorted({f.category for f in result.findings}), "injection_signals": result.injection_signals, "original_prompt_sha256": result.original_prompt_sha256})
    return result


@app.post("/api/requests", response_model=GatewayResponse)
async def gateway(request: GatewayRequest):
    result = make_analysis(request)
    overridden = request.review_override and result.decision == "block"
    if result.decision == "block" and not overridden:
        audit.write({"request_id": result.request_id, "event": "blocked", "application_id": request.application_id, "user_id": request.user_id, "policy_id": result.policy_id, "decision": result.decision, "risk_level": result.risk_level, "finding_categories": sorted({f.category for f in result.findings}), "injection_signals": result.injection_signals, "original_prompt_sha256": result.original_prompt_sha256})
        return GatewayResponse(analysis=result)
    upstream = await complete(result.protected_prompt)
    audit.write({"request_id": result.request_id, "event": "forwarded", "application_id": request.application_id, "user_id": request.user_id, "policy_id": result.policy_id, "decision": "override" if overridden else result.decision, "risk_level": result.risk_level, "finding_categories": sorted({f.category for f in result.findings}), "injection_signals": result.injection_signals, "original_prompt_sha256": result.original_prompt_sha256})
    return GatewayResponse(analysis=result, upstream=upstream)


@app.get("/api/policies", response_model=list[Policy])
async def policies():
    return store.all()


@app.put("/api/policies/{policy_id}", response_model=Policy)
async def update_policy(policy_id: str, policy: Policy):
    if not policy_id or policy_id == "default":
        raise HTTPException(400, "A concrete policy id is required")
    return store.put(policy_id, policy)


@app.get("/api/audit")
async def get_audit(limit: int = 100):
    return audit.read(max(1, min(limit, 500)))
