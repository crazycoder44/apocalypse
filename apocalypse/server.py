import json
import queue
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse

from .config import Settings
from .engine import run_security_scan

app = FastAPI(
    title="Project Apocalypse — Security Intelligence API",
    description="Enterprise Risk Intelligence & Autonomous Response Platform (Security Arm)",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FIXTURE_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "security.json"


@app.get("/api/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy", "service": "Project Apocalypse Security API"}


@app.get("/api/security/scan")
def trigger_scan(
    fixture: bool = Query(False, description="Use local fixture instead of live Microsoft tenant"),
    heuristic_only: bool = Query(False, description="Bypass AI reasoning and use heuristic analyzer"),
    model: str | None = Query(None, description="Optional Groq model override"),
) -> dict[str, Any]:
    """Single-shot HTTP GET endpoint returning full JSON evaluation."""
    fixture_path = FIXTURE_DEFAULT_PATH if fixture else None
    try:
        return run_security_scan(
            fixture_path=fixture_path,
            heuristic_only=heuristic_only,
            model=model,
        )
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err)) from err


import json
import queue
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from pydantic import BaseModel

from .config import Settings
from .engine import run_agent_chat, run_security_scan

app = FastAPI(
    title="Project Apocalypse — Security Intelligence API",
    description="Enterprise Risk Intelligence & Autonomous Response Platform (Backend Service)",
    version="0.1.0",
)

# Enable CORS for standalone frontend (e.g., http://localhost:3000, http://localhost:5173, http://127.0.0.1:3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FIXTURE_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "security.json"


@app.get("/")
def root_info() -> dict[str, str]:
    return {
        "service": "Project Apocalypse API",
        "status": "online",
        "docs": "/docs",
        "health": "/api/health",
        "scan_stream": "/api/security/scan/stream",
        "scan_json": "/api/security/scan",
        "agent_chat": "/api/agent/chat",
    }


@app.get("/api/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy", "service": "Project Apocalypse Security API"}


@app.get("/api/security/scan")
def trigger_scan(
    fixture: bool = Query(False, description="Use local fixture instead of live Microsoft tenant"),
    heuristic_only: bool = Query(False, description="Bypass AI reasoning and use heuristic analyzer"),
    model: str | None = Query(None, description="Optional Groq model override"),
) -> dict[str, Any]:
    """Single-shot HTTP GET endpoint returning full JSON evaluation."""
    fixture_path = FIXTURE_DEFAULT_PATH if fixture else None
    try:
        return run_security_scan(
            fixture_path=fixture_path,
            heuristic_only=heuristic_only,
            model=model,
        )
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err)) from err


@app.get("/api/security/scan/stream")
def trigger_scan_stream(
    fixture: bool = Query(False, description="Use local fixture instead of live Microsoft tenant"),
    heuristic_only: bool = Query(False, description="Bypass AI reasoning and use heuristic analyzer"),
    model: str | None = Query(None, description="Optional Groq model override"),
) -> StreamingResponse:
    """Server-Sent Events (SSE) streaming endpoint providing live status updates followed by final JSON evaluation."""
    fixture_path = FIXTURE_DEFAULT_PATH if fixture else None

    def event_stream() -> Iterator[str]:
        msg_queue: queue.Queue[dict[str, Any] | None] = queue.Queue()

        def push_progress(msg: str) -> None:
            msg_queue.put({"type": "status", "message": msg})

        result_container: dict[str, Any] = {}
        error_container: dict[str, str] = {}

        def background_worker() -> None:
            try:
                res = run_security_scan(
                    progress=push_progress,
                    fixture_path=fixture_path,
                    heuristic_only=heuristic_only,
                    model=model,
                )
                result_container["data"] = res
            except Exception as ex:
                error_container["error"] = str(ex)
            finally:
                msg_queue.put(None)  # Sentinel to end stream

        thread = threading.Thread(target=background_worker, daemon=True)
        thread.start()

        while True:
            item = msg_queue.get()
            if item is None:
                break
            yield f"data: {json.dumps(item)}\n\n"

        thread.join()

        if "error" in error_container:
            yield f"data: {json.dumps({'type': 'error', 'message': error_container['error']})}\n\n"
        elif "data" in result_container:
            yield f"data: {json.dumps({'type': 'result', 'payload': result_container['data']})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


class AgentChatRequest(BaseModel):
    message: str
    fixture: bool = False
    model: str | None = None
    context: dict[str, Any] | None = None


@app.post("/api/agent/chat")
def agent_chat(payload: AgentChatRequest) -> dict[str, Any]:
    """Conversational endpoint: sends the operator's chat message plus current Microsoft tenant
    security telemetry to Groq using a dedicated chat system prompt, returning a plain-text reply."""
    if not payload.message or not payload.message.strip():
        raise HTTPException(status_code=400, detail="message is required")

    fixture_path = FIXTURE_DEFAULT_PATH if payload.fixture else None
    try:
        result = run_agent_chat(
            message=payload.message,
            fixture_path=fixture_path,
            model=payload.model,
        )
        return {
            "reply": result["reply"],
            "engine": result["engine"],
            "recordsAnalyzed": result["records_analyzed"],
            "actionsTaken": result["actions_taken"],
        }
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err)) from err

