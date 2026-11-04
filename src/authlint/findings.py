"""Finding model shared by every check."""

from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITIES = ("info", "low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    """Return the position of a severity, so "high" > "low"."""
    return SEVERITIES.index(severity)


@dataclass(frozen=True)
class Finding:
    """One problem found in a provider, a client or a key set."""

    rule: str
    severity: str
    title: str
    detail: str
    fix: str
    location: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity}")

    def to_dict(self) -> dict:
        return asdict(self)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by rule id, so output is stable."""
    return sorted(findings, key=lambda f: (-severity_rank(f.severity), f.rule, f.location))
