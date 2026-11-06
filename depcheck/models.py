"""Modelos de datos."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {0: "Informativo", 1: "Baja", 2: "Media", 3: "Alta", 4: "Crítica"}[int(self)]


@dataclass
class Finding:
    package: str
    version: str
    vuln_id: str
    severity: Severity
    summary: str
    fixed_version: str | None = None
    reference: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["severity_label"] = self.severity.label
        return d


@dataclass
class ScanResult:
    manifest: str
    ecosystem: str
    started_at: str
    finished_at: str = ""
    packages_checked: int = 0
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.package))

    def summary(self) -> dict[str, int]:
        counts = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "manifest": self.manifest,
            "ecosystem": self.ecosystem,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "packages_checked": self.packages_checked,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "notes": self.notes,
            "errors": self.errors,
        }
