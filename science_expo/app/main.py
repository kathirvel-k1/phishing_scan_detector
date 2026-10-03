from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.ai_agent import get_model_name, is_openai_configured
from app.analyzer import analyze_message, analyze_message_with_agent
from app.schemas import AnalyzeRequest, AnalyzeResponse


BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="PhishGuard",
    description="An explainable demo for checking suspicious messages and URLs.",
    version="1.0.0",
)
# Permit local IDE previews (Live Server/file preview) to call the local API.
# This is for development on the same machine, not a production CORS policy.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(https?://(localhost|127\.0\.0\.1)(:\d+)?|null)$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/", include_in_schema=False)
async def home() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/index.html", include_in_schema=False)
async def home_file() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/agent", include_in_schema=False)
@app.get("/agent.html", include_in_schema=False)
async def demo_agent_page() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "agent.html")


@app.get("/app.css", include_in_schema=False)
async def stylesheet() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "app.css", media_type="text/css")


@app.get("/app.js", include_in_schema=False)
async def frontend_script() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "app.js", media_type="text/javascript")


@app.get("/agent.css", include_in_schema=False)
async def demo_agent_stylesheet() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "agent.css", media_type="text/css")


@app.get("/agent.js", include_in_schema=False)
async def demo_agent_script() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "agent.js", media_type="text/javascript")


@app.get("/api/health")
async def health() -> dict[str, str | bool]:
    ai_enabled = is_openai_configured()
    return {
        "status": "ok",
        "service": "PhishGuard analysis agent",
        "provider": "openai" if ai_enabled else "demo",
        "model": get_model_name() if ai_enabled else "demo-local-nlp",
        "openai_configured": ai_enabled,
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    message = request.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Paste a message or URL to analyze.")
    return await analyze_message_with_agent(message)


@app.post("/api/demo/analyze", response_model=AnalyzeResponse)
async def analyze_demo(request: AnalyzeRequest) -> AnalyzeResponse:
    message = request.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Paste a message or URL to analyze.")
    result = analyze_message(message)
    return result.model_copy(update={"analysis_mode": "Demo AI agent (local simulation)"})
