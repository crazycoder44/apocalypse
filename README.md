# Project Apocalypse Security Intelligence Platform

Project Apocalypse is a security analysis service for Microsoft cloud environments. It collects recent identity and incident telemetry, analyzes related signals, and returns findings for security operators. The current implementation covers security data only; it does not connect to project-management or business-intelligence systems.

## What It Does

The collection layer reads Microsoft Entra ID directory audits and sign-in activity through Microsoft Graph, Microsoft Defender incidents, and optionally Microsoft Sentinel results from a configured URL. Collection is bounded by a configurable lookback period and maximum record count. Individual sources that fail to respond are skipped so the scan can continue with available signals.

The analysis layer uses Groq when `GROQ_API_KEY` is configured. It asks the Apocalypse Security Agent to correlate events into threat narratives and return an enterprise security score, threat level, affected entities, confidence, estimated blast radius, and recommended controls. Without a Groq key, or when `--heuristic-only` is selected, the service uses its baseline heuristic analyzer and returns findings without an AI-generated enterprise score. A failed AI analysis also falls back to the heuristic analyzer.

Results are available as JSON, formatted CLI output, or a Server-Sent Events (SSE) stream with progress updates. The service provides analysis and recommendations; it does not perform remediation actions against the live Microsoft tenant.

## Requirements

- Python 3.10 or later
- Microsoft Entra application credentials with permission to read the Microsoft security data you want to analyze
- A Groq API key for AI analysis and the conversational agent; heuristic analysis does not require one
- Python packages `fastapi`, `uvicorn`, and `pydantic` to run the web API

Install the API dependencies into your active Python environment:

```powershell
python -m pip install fastapi uvicorn pydantic
```

## Configuration

Create a `.env` file in the project root, or define these values in the process environment:

| Variable | Required | Purpose |
| --- | --- | --- |
| `APOCALYPSE_TENANT_ID` | Yes for live collection | Microsoft Entra tenant ID |
| `APOCALYPSE_CLIENT_ID` | Yes for live collection | Entra application (client) ID |
| `APOCALYPSE_CLIENT_SECRET` | Yes for live collection | Entra application secret |
| `GROQ_API_KEY` | No | Enables Groq analysis and agent chat; scans otherwise use heuristics |
| `GROQ_MODEL` | No | Groq model name; defaults to `openai/gpt-oss-120b` |
| `GROQ_REASONING_EFFORT` | No | Groq reasoning effort; defaults to `medium` |
| `APOCALYPSE_LOOKBACK_HOURS` | No | Hours of identity activity to query; defaults to `24` |
| `APOCALYPSE_MAX_RECORDS` | No | Maximum records collected per source; defaults to `100` |
| `APOCALYPSE_DEFENDER_URL` | No | Optional Defender endpoint override |
| `APOCALYPSE_SENTINEL_URL` | No | Optional Sentinel results endpoint |

Grant the Entra application the appropriate read permissions and tenant consent before running a live scan. Keep `.env` and its secrets out of source control.

## Run the API

From the project root, start the FastAPI service:

```powershell
python server.py
```

The service listens on `http://localhost:8000`. Open `/docs` for the interactive API reference. The `/` route returns service and endpoint information, and `/api/health` is a lightweight health check.

## Run a Scan from the CLI

With the live-collection credentials configured, run:

```powershell
python -m apocalypse
```

For JSON output or the baseline heuristic analyzer:

```powershell
python -m apocalypse --json
python -m apocalypse --heuristic-only
```

Use `--model MODEL_NAME` to override the configured Groq model for a scan. The CLI also supports `--raw-groq` to print the structured model result as JSON.

## API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/api/health` | Service health status |
| `GET` | `/api/security/scan` | Run a scan and return the complete JSON result |
| `GET` | `/api/security/scan/stream` | Run a scan and stream progress and the final result as SSE |
| `POST` | `/api/agent/chat` | Ask the security agent a question about current security telemetry |
| `GET` | `/docs` | Interactive Swagger API reference |

Both scan endpoints accept `heuristic_only=true` to bypass Groq reasoning and an optional `model` parameter to select a Groq model. The chat endpoint requires `GROQ_API_KEY`.

## Project Layout

- `apocalypse/collectors.py` retrieves and normalizes signals from Microsoft sources.
- `apocalypse/microsoft.py` handles Microsoft authentication and HTTP requests.
- `apocalypse/engine.py` coordinates collection, analysis, and result assembly.
- `apocalypse/analyzer.py` contains the baseline heuristic analysis.
- `apocalypse/ai.py` defines Groq analysis and conversational-agent behavior.
- `apocalypse/server.py` exposes the FastAPI endpoints; `server.py` is the local entry point.
- `apocalypse/cli.py` implements command-line scans.