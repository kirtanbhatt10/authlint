"""Render results as text, JSON, Markdown or SARIF."""

from __future__ import annotations

import json

from . import __version__
from .findings import SEVERITIES, Finding
from .rules import RULES

FORMATS = ("text", "json", "markdown", "sarif")
COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def counts(findings: list[Finding]) -> dict[str, int]:
    return {sev: sum(1 for f in findings if f.severity == sev) for sev in reversed(SEVERITIES)}


def render_text(results: list[dict], color: bool = False) -> str:
    lines = [f"authlint {__version__}", ""]
    for result in results:
        findings = result["findings"]
        lines.append(f"{result['source']}  ({result['target']})")
        if not findings:
            lines += ["  no findings", ""]
            continue
        summary = ", ".join(f"{n} {sev}" for sev, n in counts(findings).items() if n)
        lines.append(f"  {len(findings)} finding(s): {summary}")
        for f in findings:
            sev = f.severity.upper().ljust(8)
            if color:
                sev = COLORS[f.severity] + sev + "\033[0m"
            lines.append(f"  {sev} {f.rule}  {f.title}")
            lines.append(f"           {f.detail}")
            lines.append(f"           fix: {f.fix}")
        lines.append("")
    return "\n".join(lines)


def render_json(results: list[dict]) -> str:
    payload = {
        "tool": "authlint",
        "version": __version__,
        "results": [
            {
                "source": r["source"],
                "target": r["target"],
                "counts": counts(r["findings"]),
                "findings": [f.to_dict() for f in r["findings"]],
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2)


def render_markdown(results: list[dict]) -> str:
    lines = ["## authlint report", ""]
    for result in results:
        lines.append(f"### {result['target']}: `{result['source']}`")
        lines.append("")
        if not result["findings"]:
            lines += ["No findings.", ""]
            continue
        lines += ["| Severity | Rule | Finding | Fix |", "| --- | --- | --- | --- |"]
        for f in result["findings"]:
            lines.append(f"| {f.severity} | {f.rule} | {_cell(f.title)}: {_cell(f.detail)} | {_cell(f.fix)} |")
        lines.append("")
    return "\n".join(lines)


def render_sarif(results: list[dict]) -> str:
    used = sorted({f.rule for r in results for f in r["findings"]})
    rules = [
        {
            "id": rule_id,
            "name": RULES[rule_id].title,
            "shortDescription": {"text": RULES[rule_id].title},
            "help": {"text": RULES[rule_id].reference},
            "properties": {"security-severity": _security_severity(RULES[rule_id].severity)},
        }
        for rule_id in used
    ]
    sarif_results = []
    for r in results:
        for f in r["findings"]:
            sarif_results.append(
                {
                    "ruleId": f.rule,
                    "level": SARIF_LEVEL[f.severity],
                    "message": {"text": f"{f.detail} Fix: {f.fix}"},
                    "locations": [
                        {
                            "physicalLocation": {"artifactLocation": {"uri": r["source"]}},
                            "logicalLocations": [{"name": f.location or r["target"]}],
                        }
                    ],
                }
            )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "authlint",
                        "version": __version__,
                        "informationUri": "https://github.com/kirtanbhatt10/authlint",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _security_severity(severity: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}[severity]


def render(results: list[dict], fmt: str, color: bool = False) -> str:
    if fmt == "json":
        return render_json(results)
    if fmt == "markdown":
        return render_markdown(results)
    if fmt == "sarif":
        return render_sarif(results)
    return render_text(results, color)
