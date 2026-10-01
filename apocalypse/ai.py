import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .models import Finding, SecurityRecord

DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b"

APOCALYPSE_SYSTEM_PROMPT = """You are the Apocalypse Security Intelligence Agent, the core reasoning brain of Project Apocalypse.

Your role:
1. Analyze raw and normalized enterprise security signals (Entra ID sign-ins, directory audit logs, Microsoft Defender incidents, Sentinel alerts, and cloud telemetry).
2. Correlate disparate events across time, users, and workloads into unified attack chains / threat narratives (e.g., suspicious sign-in -> role elevation -> credential addition -> exfiltration).
3. Determine:
   - Enterprise Security Risk Score (0-100, where 100 is severe imminent compromise)
   - Overall Threat Level (LOW, MEDIUM, HIGH, CRITICAL)
   - Perceived Threats with confidence, severity, affected entities, and predicted blast radius / attacker next moves.
   - Recommended Microsoft Security Controls and precise mitigation steps (Entra PIM, Conditional Access, Defender XDR containment, Access Reviews, etc.).

Strict Output Requirement:
You MUST respond with valid JSON ONLY matching the following schema:
{
  "enterprise_security_score": <int 0-100>,
  "overall_threat_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "executive_summary": "<string>",
  "perceived_threats": [
    {
      "title": "<string>",
      "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
      "confidence": <float 0.0-1.0>,
      "category": "<identity|privilege|credential|incident|data_exposure|infrastructure>",
      "affected_entities": ["<string>"],
      "attack_chain_narrative": "<string>",
      "predicted_blast_radius": "<string>",
      "evidence": ["<string>"],
      "recommendations": {
        "immediate_action": "<string>",
        "recommended_microsoft_controls": ["<string>"]
      }
    }
  ]
}
Do not include any conversational text, markdown formatting outside json or code block markers. Output pure JSON only.
"""

APOCALYPSE_CHAT_SYSTEM_PROMPT = """You are the Apocalypse Security Intelligence Agent, speaking directly to an enterprise operator in a governed chat console.

Your role:
1. Answer the operator's questions using ONLY the enterprise security telemetry signals provided to you (Entra ID sign-ins, directory audit logs, Microsoft Defender incidents, Sentinel alerts, and related cloud telemetry).
2. Correlate disparate events across time, users, and workloads into clear threat narratives (e.g., suspicious sign-in -> role elevation -> credential addition -> exfiltration) when relevant to the question.
3. Speak like a precise, senior security analyst: direct, factual, and concise. Do not pad with filler.

Strict scope boundary:
You currently have access to security telemetry ONLY. You do NOT have access to project management data or business intelligence data (e.g., project timelines, delivery status, revenue, contracts, customer accounts) for this tenant.
If the operator asks about anything that is not security-related — including projects, project status, or business intelligence — you MUST reply that you do not currently have access to project or business data for the tenant yet, and that you can provide insights on that once it is available. Do not speculate or fabricate project or business details under any circumstances.

Output format:
Respond with plain, natural conversational text only. Do NOT output JSON, and do NOT wrap your answer in markdown code fences.

Remediation actions:
If a `resolve_security_finding` tool is available to you and the operator explicitly asks you to remediate, resolve, close, or clear a specific finding, threat, or risk that is present in the provided security signals, call the tool with the matching signal's "id". Only resolve signals that clearly correspond to what the operator asked about — if it is ambiguous which signal they mean, ask for clarification instead of guessing. If no tool is available, or the operator's request does not match a specific signal in the provided list, explain what you would recommend instead of claiming the action was taken. After a tool call completes, confirm in plain language what was resolved.

Resolved findings:
The security signals list you are given always reflects the CURRENT state only — any finding that has already been resolved/remediated has already been removed from that list before it reached you. You will never see a signal marked resolved. This means:
- Never claim a finding still needs attention if it is not present in the current signals list, even if it was mentioned earlier in this conversation.
- If the signals list is empty, or none of the remaining signals relate to what the operator is asking about, say clearly that there are no current security risks discovered (for that scope), rather than restating old findings from earlier in the conversation.
- If the operator asks for their "current" standing, always answer strictly from the current signals list, not from what you said previously.
"""


RESOLVE_FINDING_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "resolve_security_finding",
        "description": (
            "Mark a specific security signal from the provided signals list as resolved/remediated in the "
            "demo tenant dataset, so it is excluded from future security analysis and chat answers. Only call "
            "this when the operator explicitly asks you to resolve, remediate, close, or clear a specific "
            "finding that is present in the provided security signals list."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "signal_id": {
                    "type": "integer",
                    "description": "The integer 'id' of the signal from the provided security signals list to resolve.",
                },
                "resolution_note": {
                    "type": "string",
                    "description": "A brief note on the remediation action taken, for audit purposes.",
                },
            },
            "required": ["signal_id", "resolution_note"],
        },
    },
}


@dataclass
class AIAnalysisResult:
    enterprise_security_score: int
    overall_threat_level: str
    executive_summary: str
    perceived_threats: list[dict[str, Any]] = field(default_factory=list)
    raw_response: str = ""

    def to_findings(self) -> list[Finding]:
        findings = []
        for threat in self.perceived_threats:
            title = threat.get("title", "Security Threat")
            severity = str(threat.get("severity", "medium")).lower()
            category = threat.get("category", "security")
            evidence = threat.get("evidence", [])
            
            recs = threat.get("recommendations", {})
            immediate = recs.get("immediate_action", "")
            controls = ", ".join(recs.get("recommended_microsoft_controls", []))
            rec_str = f"{immediate} (Recommended Controls: {controls})" if controls else immediate

            finding = Finding(
                source="Apocalypse AI Agent (Groq)",
                kind=category,
                title=title,
                severity=severity,
                evidence=evidence,
                recommendation=rec_str,
                record=threat,
            )
            findings.append(finding)
        return findings


def _safe_dict(val: Any) -> dict[str, Any]:
    return val if isinstance(val, dict) else {}


def _safe_list(val: Any) -> list[Any]:
    return val if isinstance(val, list) else []


def condense_record(r: SecurityRecord, idx: int) -> dict[str, Any]:
    """Extract essential security fields and strip verbose metadata to optimize token budget."""
    raw = _safe_dict(r.data)
    condensed: dict[str, Any] = {
        "id": idx,
        "source": r.source,
        "type": r.kind,
    }

    if r.kind == "sign_in":
        status_obj = _safe_dict(raw.get("status"))
        loc_obj = _safe_dict(raw.get("location"))
        error_code = status_obj.get("errorCode", 0) or 0
        city = loc_obj.get("city") or ""
        country = loc_obj.get("countryOrRegion") or ""
        loc_str = f"{city}, {country}".strip(", ")

        condensed.update({
            "time": raw.get("createdDateTime"),
            "user": raw.get("userPrincipalName") or raw.get("userDisplayName"),
            "app": raw.get("appDisplayName"),
            "ip": raw.get("ipAddress"),
            "location": loc_str if loc_str else None,
            "status": "Failed" if error_code != 0 else "Success",
            "error_code": error_code if error_code != 0 else None,
            "failure_reason": status_obj.get("failureReason"),
            "risk_state": raw.get("riskState"),
            "risk_level": raw.get("riskLevelAggregated"),
            "ca_status": raw.get("conditionalAccessStatus"),
        })
    elif r.kind == "directory_audit":
        initiated_by = _safe_dict(raw.get("initiatedBy"))
        user_obj = _safe_dict(initiated_by.get("user"))
        app_obj = _safe_dict(initiated_by.get("app"))
        actor = (
            user_obj.get("userPrincipalName")
            or user_obj.get("displayName")
            or app_obj.get("displayName")
            or app_obj.get("servicePrincipalName")
            or "System"
        )
        targets = []
        for t in _safe_list(raw.get("targetResources")):
            if not isinstance(t, dict):
                continue
            t_name = t.get("displayName") or t.get("userPrincipalName") or t.get("type")
            mods = []
            for m in _safe_list(t.get("modifiedProperties")):
                if isinstance(m, dict) and m.get("displayName"):
                    mods.append(f"{m.get('displayName')}: {m.get('oldValue')} -> {m.get('newValue')}")
            targets.append({"name": t_name, "type": t.get("type"), "changes": mods[:3]})

        condensed.update({
            "time": raw.get("activityDateTime"),
            "activity": raw.get("activityDisplayName"),
            "category": raw.get("category"),
            "result": raw.get("result"),
            "actor": actor,
            "targets": targets[:3] if targets else None,
        })
    elif r.kind == "incident":
        condensed.update({
            "time": raw.get("createdDateTime"),
            "incident_id": raw.get("id") or raw.get("incidentId"),
            "title": raw.get("title") or raw.get("displayName"),
            "severity": raw.get("severity"),
            "status": raw.get("status"),
            "classification": raw.get("classification"),
            "description": raw.get("description"),
        })
    else:
        condensed["data"] = {k: v for k, v in raw.items() if k not in ("@odata.context", "@odata.etag")}

    # Clean out None or empty values
    return {k: v for k, v in condensed.items() if v not in (None, "", [], {})}


def deduplicate_and_filter_noise(condensed_list: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Group repetitive routine background sync actions into count summaries to save token space."""
    noise_counts: dict[str, int] = {}
    signal_bucket: list[dict[str, Any]] = []

    for item in condensed_list:
        activity = item.get("activity", "")
        actor = item.get("actor", "")
        # High volume benign background events (e.g. AAD Connect syncs, routine password syncs)
        if activity in ("Synchronization rule action", "Import") and actor in ("System", "Sync_Account", "Sync"):
            noise_counts[activity] = noise_counts.get(activity, 0) + 1
        else:
            signal_bucket.append(item)

    return signal_bucket, noise_counts


def prepare_signals_summary(records: list[SecurityRecord], max_signals: int = 15) -> list[dict[str, Any]]:
    """Sanitize, condense, and prioritize anomalous/risky records for LLM context limits.

    Signal "id" values are assigned by position in the full `records` list (1-based) so they stay stable
    across calls, even though resolved records are skipped here and never reach the LLM.
    """
    condensed_list = [
        condense_record(r, idx)
        for idx, r in enumerate(records, start=1)
        if not (isinstance(r.data, dict) and r.data.get("resolved") is True)
    ]
    clean_signals, noise_counts = deduplicate_and_filter_noise(condensed_list)

    # Prioritize interesting/anomalous signals first (failures, risks, role/privilege changes, credentials)
    def priority_score(item: dict[str, Any]) -> int:
        text = json.dumps(item).lower()
        score = 0
        if "fail" in text or "error" in text:
            score += 4
        if "risk" in text:
            score += 5
        if "role" in text or "admin" in text or "privilege" in text:
            score += 4
        if "credential" in text or "secret" in text or "serviceprincipal" in text:
            score += 4
        if item.get("type") == "incident":
            score += 6
        return score

    sorted_signals = sorted(clean_signals, key=priority_score, reverse=True)
    selected = sorted_signals[:max_signals]

    if noise_counts:
        selected.append({
            "id": "AGGREGATED_BACKGROUND_NOISE",
            "type": "summary",
            "note": "Routine benign synchronization actions suppressed to save context",
            "suppressed_events": noise_counts,
        })

    return selected


def _call_groq_api(
    messages: list[dict[str, Any]],
    api_key: str,
    model: str,
    reasoning_effort: str | None = None,
    json_mode: bool = True,
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    url = "https://api.groq.com/openai/v1/chat/completions"
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"

    if reasoning_effort:
        payload["reasoning_effort"] = reasoning_effort
    elif "gpt-oss" in model:
        payload["reasoning_effort"] = "medium"

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ApocalypseSecurityAgent/1.0 (Enterprise Risk Intelligence)",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", "replace")
        raise RuntimeError(f"Groq API call failed ({err.code}): {body}") from err
    except urllib.error.URLError as err:
        raise RuntimeError(f"Groq network connection failed: {err}") from err


def analyze_with_groq(
    records: list[SecurityRecord],
    api_key: str,
    model: str = DEFAULT_GROQ_MODEL,
    reasoning_effort: str | None = None,
) -> AIAnalysisResult:
    """Send security signals to Groq LLM for reasoning and threat extraction."""
    if not api_key:
        raise ValueError("GROQ_API_KEY is required for AI reasoning.")

    # High signal-to-noise preparation
    signals = prepare_signals_summary(records, max_signals=15)
    user_prompt = f"""Analyze the following {len(signals)} prioritized enterprise security telemetry signals and produce the risk intelligence evaluation:

Security Signals:
{json.dumps(signals, indent=2)}
"""

    messages = [
        {"role": "system", "content": APOCALYPSE_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    data = _call_groq_api(messages, api_key=api_key, model=model, reasoning_effort=reasoning_effort)
    choices = data.get("choices", [])
    if not choices:
        raise RuntimeError(f"Empty choices in Groq response: {data}")

    content = choices[0].get("message", {}).get("content", "")
    if not content:
        raise RuntimeError(f"No content in Groq completion message: {data}")

    try:
        parsed = json.loads(content)
        return AIAnalysisResult(
            enterprise_security_score=parsed.get("enterprise_security_score", 0),
            overall_threat_level=parsed.get("overall_threat_level", "UNKNOWN"),
            executive_summary=parsed.get("executive_summary", ""),
            perceived_threats=parsed.get("perceived_threats", []),
            raw_response=content,
        )
    except json.JSONDecodeError as err:
        raise RuntimeError(f"Failed to parse model JSON response: {content}") from err


@dataclass
class AIChatResult:
    reply: str
    raw_response: str = ""
    actions_taken: list[dict[str, Any]] = field(default_factory=list)


def chat_with_groq(
    records: list[SecurityRecord],
    user_message: str,
    api_key: str,
    model: str = DEFAULT_GROQ_MODEL,
    reasoning_effort: str | None = None,
    on_resolve_finding: Callable[[int, str], str] | None = None,
) -> AIChatResult:
    """Send a conversational operator message plus current security telemetry to Groq and return a plain-text reply.

    If `on_resolve_finding` is provided, the model is also given a `resolve_security_finding` tool it may call
    when the operator explicitly asks to remediate/resolve a specific signal. The callback is invoked with
    (signal_id, resolution_note) and must return a short string describing the outcome, which is fed back to
    the model so it can confirm the action in its final reply. When omitted (e.g. for live-tenant chats), the
    tool is never offered, so the model cannot mutate anything.
    """
    if not api_key:
        raise ValueError("GROQ_API_KEY is required for AI reasoning.")

    signals = prepare_signals_summary(records, max_signals=15)
    signals_note = (
        "No unresolved security signals — all clear."
        if not signals
        else f"{len(signals)} prioritized signal(s), current as of right now. Each signal has a stable \"id\" you can reference."
    )
    user_prompt = f"""Current enterprise security telemetry signals ({signals_note}):
{json.dumps(signals, indent=2)}

Operator message:
{user_message}
"""

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": APOCALYPSE_CHAT_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    tools = [RESOLVE_FINDING_TOOL] if on_resolve_finding else None
    actions_taken: list[dict[str, Any]] = []

    # Loop so the model can resolve several signals across multiple turns (e.g. "fix all the risky ones"),
    # not just a single tool call. Capped to avoid runaway back-and-forth with the API.
    max_tool_rounds = 5
    message: dict[str, Any] = {}
    for _ in range(max_tool_rounds + 1):
        data = _call_groq_api(
            messages,
            api_key=api_key,
            model=model,
            reasoning_effort=reasoning_effort,
            json_mode=False,
            tools=tools,
        )
        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError(f"Empty choices in Groq response: {data}")

        message = choices[0].get("message", {})
        tool_calls = message.get("tool_calls") or []

        if not tool_calls or not on_resolve_finding:
            break

        messages.append(message)
        for call in tool_calls:
            function = call.get("function", {})
            if function.get("name") != "resolve_security_finding":
                continue
            try:
                args = json.loads(function.get("arguments") or "{}")
                signal_id = int(args["signal_id"])
                resolution_note = str(args.get("resolution_note", ""))
                outcome = on_resolve_finding(signal_id, resolution_note)
            except Exception as ex:
                outcome = f"Failed to resolve the requested signal: {ex}"
                signal_id = None
                resolution_note = None
            actions_taken.append({
                "signal_id": signal_id,
                "resolution_note": resolution_note,
                "outcome": outcome,
            })
            messages.append({
                "role": "tool",
                "tool_call_id": call.get("id"),
                "name": "resolve_security_finding",
                "content": outcome,
            })

    content = message.get("content", "")
    if not content:
        if actions_taken:
            # The model resolved everything it needed to but ran out of rounds before replying in text.
            content = "Resolved the requested findings in the demo dataset."
        else:
            raise RuntimeError(f"No content in Groq completion message: {message}")

    return AIChatResult(reply=content, raw_response=content, actions_taken=actions_taken)
