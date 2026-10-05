"""SARIF file parsing and result transformation."""

from __future__ import annotations

import json
from pathlib import Path

from miner.models import Finding

#agregamos helpers
def _security_severity(rule_info: dict) -> float | None:
    raw = rule_info.get("properties", {}).get("security-severity")
    try:
        return float(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _cwes(rule_info: dict) -> list[str]:
    cwes: set[str] = set()
    for tag in rule_info.get("properties", {}).get("tags", []):
        if tag.startswith("external/cwe/cwe-"):
            try:
                cwes.add(f"CWE-{int(tag.rsplit('-', 1)[1])}")
            except ValueError:
                continue
    return sorted(cwes)

def parse_sarif(sarif_path: Path) -> list[Finding]:
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    findings: list[Finding] = []

    for run in sarif_data.get("runs", []):
        tool = run.get("tool", {})
        components = [tool.get("driver", {}), *tool.get("extensions", [])]
        rules = {r["id"]: r for c in components for r in c.get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")

            rule_info = rules.get(rule_id, {})
            default_severity = "warning"
            for prop in rule_info.get("properties", {}).get("tags", []):
                if prop.startswith("security-severity"):
                    severity_val = float(prop.split(":")[-1]) if ":" in prop else 0
                    if severity_val >= 9.0:
                        default_severity = "error"
                    elif severity_val >= 7.0:
                        default_severity = "warning"
                    elif severity_val >= 4.0:
                        default_severity = "note"
                    else:
                        default_severity = "none"
                    break

            level = result.get("level", default_severity)

            for loc in result.get("locations", []):
                physical = loc.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})

                file_path = artifact.get("uri", "unknown")
                start_line = region.get("startLine", 0)
                end_line = region.get("endLine")

                code_snippet = region.get("snippet", {}).get("text")

                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=level,
                        message=message,
                        file=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        code_snippet=code_snippet,
                        rule_name=(rule_info.get("shortDescription") or {}).get("text")
                        or rule_info.get("name"),
                        cwe=_cwes(rule_info),
                        security_severity=_security_severity(rule_info),
                    )
                )

    return findings
