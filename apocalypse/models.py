from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    source: str
    kind: str
    title: str
    severity: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    record: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityRecord:
    source: str
    kind: str
    data: dict[str, Any]