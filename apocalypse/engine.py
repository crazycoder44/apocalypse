import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .ai import DEFAULT_GROQ_MODEL, analyze_with_groq, chat_with_groq
from .analyzer import analyze as heuristic_analyze
from .collectors import collect_defender, collect_graph, collect_sentinel
from .config import Settings
from .microsoft import MicrosoftClient
from .models import SecurityRecord

ProgressCallback = Callable[[str], None]


def load_fixture_records(path: Path) -> list[SecurityRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [SecurityRecord(item["source"], item["kind"], item["data"]) for item in payload]


def _gather_records(
    settings: Settings,
    fixture_path: Path | None = None,
    log: ProgressCallback = lambda msg: None,
) -> list[SecurityRecord]:
    """Collect security signals from the local fixture or the live Microsoft tenant."""
    records: list[SecurityRecord] = []

    if fixture_path:
        log(f"Loading local security fixture records from {fixture_path.name}...")
        records = load_fixture_records(fixture_path)
        log(f"Loaded {len(records)} simulated security signals from fixture.")
    else:
        log("Validating Microsoft Entra and Azure client credentials...")
        settings.validate_live()
        client = MicrosoftClient(settings.tenant_id, settings.client_id, settings.client_secret)

        # 1. Directory Audits & Sign-ins via Graph
        records.extend(collect_graph(client, settings, progress=log))

        # 2. Defender Incidents
        records.extend(collect_defender(client, settings, progress=log))

        # 3. Sentinel Telemetry
        records.extend(collect_sentinel(client, settings, progress=log))

    return records


def run_security_scan(
    progress: ProgressCallback | None = None,
    fixture_path: Path | None = None,
    heuristic_only: bool = False,
    model: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Execute end-to-end security analysis with real-time progress reporting and structured JSON output."""
    if settings is None:
        settings = Settings()

    def log(msg: str) -> None:
        if progress:
            progress(msg)

    records = _gather_records(settings, fixture_path=fixture_path, log=log)

    log(f"Total security signals aggregated: {len(records)}")

    groq_key = settings.groq_api_key
    model_name = model or settings.groq_model
    ai_result = None
    findings = []

    if groq_key and not heuristic_only:
        log(f"Sending prioritized telemetry signals to Apocalypse Security Agent ({model_name})...")
        try:
            ai_result = analyze_with_groq(
                records,
                api_key=groq_key,
                model=model_name,
                reasoning_effort=settings.groq_reasoning_effort,
            )
            findings = ai_result.to_findings()
            log("AI threat correlation and attack-chain analysis completed successfully.")
        except Exception as ex:
            log(f"Warning: AI reasoning encountered an error ({ex}). Running baseline heuristic analyzer...")
            findings = heuristic_analyze(records)
    else:
        if not groq_key and not heuristic_only:
            log("Notice: GROQ_API_KEY not provided. Running baseline heuristic analyzer...")
        else:
            log("Running baseline heuristic analyzer (heuristic-only mode requested)...")
        findings = heuristic_analyze(records)

    log("Compiling final enterprise security risk intelligence evaluation...")

    if ai_result:
        return {
            "status": "success",
            "engine": f"Groq AI ({model_name})",
            "records_analyzed": len(records),
            "enterprise_security_score": ai_result.enterprise_security_score,
            "overall_threat_level": ai_result.overall_threat_level,
            "executive_summary": ai_result.executive_summary,
            "perceived_threats": ai_result.perceived_threats,
            "findings": [f.__dict__ for f in findings],
        }

    return {
        "status": "success",
        "engine": "Baseline Heuristic Analyzer",
        "records_analyzed": len(records),
        "enterprise_security_score": None,
        "overall_threat_level": None,
        "executive_summary": None,
        "perceived_threats": [],
        "findings": [f.__dict__ for f in findings],
    }


def _make_resolve_finding_callback(fixture_path: Path | None) -> Callable[[int, str], str] | None:
    """Build a callback that lets the chat agent mark a fixture signal as resolved on disk.

    Only wired up in fixture/demo mode — never for the live Microsoft tenant — so the model can only ever
    mutate the local demo dataset, not real security telemetry.
    """
    if fixture_path is None:
        return None

    def resolve(signal_id: int, resolution_note: str) -> str:
        try:
            payload = json.loads(fixture_path.read_text(encoding="utf-8"))
        except Exception as ex:
            return f"Could not read the demo dataset to resolve signal {signal_id}: {ex}"

        index = signal_id - 1
        if not isinstance(payload, list) or index < 0 or index >= len(payload):
            return f"No signal with id {signal_id} was found in the current demo dataset."

        entry = payload[index]
        data = entry.get("data")
        if not isinstance(data, dict):
            data = {}
            entry["data"] = data

        if data.get("resolved") is True:
            return f"Signal {signal_id} was already marked resolved."

        data["resolved"] = True
        data["resolution_note"] = resolution_note
        fixture_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return f"Signal {signal_id} has been marked resolved in the demo dataset and will be excluded from future analysis."

    return resolve


def run_agent_chat(
    message: str,
    progress: ProgressCallback | None = None,
    fixture_path: Path | None = None,
    model: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Answer a conversational operator message using current security telemetry via the Apocalypse chat agent."""
    if settings is None:
        settings = Settings()

    def log(msg: str) -> None:
        if progress:
            progress(msg)

    records = _gather_records(settings, fixture_path=fixture_path, log=log)
    log(f"Total security signals aggregated: {len(records)}")

    groq_key = settings.groq_api_key
    model_name = model or settings.groq_model
    if not groq_key:
        raise ValueError("GROQ_API_KEY is required for the Apocalypse Agent chat.")

    log(f"Sending operator message and prioritized telemetry to Apocalypse Agent ({model_name})...")
    chat_result = chat_with_groq(
        records,
        user_message=message,
        api_key=groq_key,
        model=model_name,
        reasoning_effort=settings.groq_reasoning_effort,
        on_resolve_finding=_make_resolve_finding_callback(fixture_path),
    )
    log("Apocalypse Agent chat response generated successfully.")

    return {
        "status": "success",
        "engine": f"Groq AI ({model_name})",
        "records_analyzed": len(records),
        "reply": chat_result.reply,
        "actions_taken": chat_result.actions_taken,
    }
