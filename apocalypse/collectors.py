import urllib.parse
from collections.abc import Callable
from typing import Any

from .config import Settings
from .microsoft import MicrosoftClient, since_iso
from .models import SecurityRecord

ProgressCallback = Callable[[str], None]


def _records(source: str, kind: str, payload: dict[str, Any], limit: int) -> list[SecurityRecord]:
    values = payload.get("value", [])[:limit]
    return [SecurityRecord(source, kind, value) for value in values]


def collect_graph(
    client: MicrosoftClient,
    settings: Settings,
    progress: ProgressCallback | None = None,
) -> list[SecurityRecord]:
    def log(msg: str) -> None:
        if progress:
            progress(msg)
        else:
            print(msg, flush=True)

    since = since_iso(settings.lookback_hours)
    records: list[SecurityRecord] = []

    # 1. Directory Audits: filter by 'activityDateTime'
    audit_query = urllib.parse.urlencode({
        "$filter": f"activityDateTime ge {since}",
        "$top": settings.max_records,
    })
    audit_url = f"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?{audit_query}"
    log("[*] Fetching Entra ID directory audits...")
    try:
        data = client.get_json(audit_url, "https://graph.microsoft.com/.default")
        audit_recs = _records("Microsoft Graph", "directory_audit", data, settings.max_records)
        records.extend(audit_recs)
        log(f"    -> Retrieved {len(audit_recs)} directory audit records.")
    except Exception as err:
        log(f"[!] Warning: Directory audits fetch failed ({err}). Skipping.")

    # 2. Sign-ins: filter by 'createdDateTime'
    signin_query = urllib.parse.urlencode({
        "$filter": f"createdDateTime ge {since}",
        "$top": settings.max_records,
    })
    signin_url = f"https://graph.microsoft.com/v1.0/auditLogs/signIns?{signin_query}"
    log("[*] Fetching Entra ID sign-in logs...")
    try:
        data = client.get_json(signin_url, "https://graph.microsoft.com/.default")
        signin_recs = _records("Microsoft Graph", "sign_in", data, settings.max_records)
        records.extend(signin_recs)
        log(f"    -> Retrieved {len(signin_recs)} sign-in records.")
    except Exception as err:
        log(f"[!] Warning: Sign-in logs fetch failed ({err}). Skipping.")

    return records


def collect_defender(
    client: MicrosoftClient,
    settings: Settings,
    progress: ProgressCallback | None = None,
) -> list[SecurityRecord]:
    """Collect incidents from Microsoft Graph Security / Defender endpoints with graceful fallback."""
    def log(msg: str) -> None:
        if progress:
            progress(msg)
        else:
            print(msg, flush=True)

    # 1. Standard modern unified endpoint: Microsoft Graph Security Incidents
    graph_security_url = f"https://graph.microsoft.com/v1.0/security/incidents?$top={settings.max_records}"
    log("[*] Checking Microsoft Defender XDR security incidents...")
    try:
        data = client.get_json(graph_security_url, "https://graph.microsoft.com/.default")
        incidents = _records("Microsoft Defender", "incident", data, settings.max_records)
        log(f"    -> Retrieved {len(incidents)} Defender incidents.")
        return incidents
    except Exception as graph_err:
        # 2. Legacy Defender MTP endpoint fallback if configured and Graph failed
        if settings.defender_url and "api.security.microsoft.com" in settings.defender_url:
            try:
                data = client.get_json(settings.defender_url, "https://security.microsoft.com/.default")
                return _records("Microsoft Defender", "incident", data, settings.max_records)
            except Exception:
                pass
        log(f"[*] Note: Defender incident collection skipped ({graph_err}). Continuing with Entra/Audit signals.")
        return []


def collect_sentinel(
    client: MicrosoftClient,
    settings: Settings,
    progress: ProgressCallback | None = None,
) -> list[SecurityRecord]:
    def log(msg: str) -> None:
        if progress:
            progress(msg)
        else:
            print(msg, flush=True)

    if not settings.sentinel_url:
        return []
    log("[*] Fetching Microsoft Sentinel analytics results...")
    try:
        data = client.get_json(settings.sentinel_url, "https://management.azure.com/.default")
        recs = _records("Microsoft Sentinel", "sentinel_result", data, settings.max_records)
        log(f"    -> Retrieved {len(recs)} Sentinel records.")
        return recs
    except Exception as err:
        log(f"[!] Warning: Sentinel fetch failed ({err}). Skipping.")
        return []
