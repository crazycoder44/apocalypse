from collections import Counter
from typing import Iterable

from .models import Finding, SecurityRecord


def _text(record: SecurityRecord) -> str:
    return str(record.data).lower()


def analyze(records: Iterable[SecurityRecord]) -> list[Finding]:
    records = list(records)
    findings: list[Finding] = []
    privileged_terms = ("role", "privilege", "admin", "owner")
    credential_terms = ("credential", "secret", "certificate", "service principal")
    for record in records:
        text = _text(record)
        if record.kind == "sign_in" and any(term in text for term in ("failure", "risk", "unfamiliar", "impossible")):
            findings.append(Finding(
                record.source, "identity", "Suspicious sign-in signal", "high",
                [f"A sign-in record contains risk or failure indicators: {record.data.get('userDisplayName', record.data.get('userId', 'unknown user'))}"],
                "Validate the user, location, device, and conditional-access result in Entra ID.", record.data,
            ))
        if record.kind == "directory_audit" and any(term in text for term in privileged_terms):
            findings.append(Finding(
                record.source, "privilege", "Privileged directory change requires review", "high",
                [f"Directory audit activity: {record.data.get('activityDisplayName', 'unknown activity')}"],
                "Confirm the actor and target, then review PIM activation and access-review history.", record.data,
            ))
        if any(term in text for term in credential_terms):
            findings.append(Finding(
                record.source, "credential", "Credential or service-principal activity detected", "critical",
                [f"Credential-related evidence came from {record.source} ({record.kind})."],
                "Validate the change, rotate exposed credentials if necessary, and review subsequent resource access.", record.data,
            ))
        severity = str(record.data.get("severity", "")).lower()
        if record.kind in ("incident", "sentinel_result") and severity in ("high", "critical"):
            findings.append(Finding(
                record.source, "incident", f"{severity.title()} security incident", severity,
                [str(record.data.get("title") or record.data.get("name") or "High-severity alert")],
                "Investigate the incident timeline, affected entities, and recommended containment actions.", record.data,
            ))
    duplicate_sources = Counter(record.source for record in records)
    if len(records) == 0:
        findings.append(Finding("Analyzer", "coverage", "No security records were returned", "medium", [], "Check API permissions, time range, and source configuration."))
    elif len(duplicate_sources) == 1:
        source = next(iter(duplicate_sources))
        findings.append(Finding("Analyzer", "coverage", "Security view has a single source", "medium", [f"Only {source} returned records."], "Connect at least one independent source before treating the risk view as comprehensive."))
    return findings