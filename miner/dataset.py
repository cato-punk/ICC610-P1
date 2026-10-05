"""Dataset unificado (CodeQL + Grype) construido a partir de los resultados del Miner."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .github import GitHubRepo
from .grype import iter_matches
from .models import GrypeResult, RepositoryResult

# Esquema único: todas las filas de findings.jsonl tienen exactamente estas claves.
FINDING_FIELDS = (
    "repo", "tool", "category", "vuln_id", "cwe", "title",
    "severity", "severity_score", "file", "start_line", "end_line",
    "package", "version", "ecosystem", "fix_versions",
    "message", "commit", "detected_at",
)


def _finding_row(**values) -> dict:
    unknown = set(values) - set(FINDING_FIELDS)
    if unknown:
        raise KeyError(f"Unknown finding fields: {sorted(unknown)}")
    return {field: values.get(field) for field in FINDING_FIELDS}


def _codeql_severity(score: float | None, level: str | None) -> str:
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low" if score > 0 else "info"
    return {"error": "high", "warning": "medium", "note": "low"}.get(
        (level or "").lower(), "info"
    )


def _grype_severity(raw: str | None) -> str:
    return {
        "critical": "critical", "high": "high", "medium": "medium",
        "low": "low", "negligible": "info",
    }.get((raw or "").lower(), "unknown")


def build_findings(
    organization: str,
    results: list[RepositoryResult],
    grype_results: list[GrypeResult],
) -> list[dict]:
    detected_at = datetime.now(timezone.utc).isoformat()
    grype_by_repo = {g.full_name: g for g in grype_results}
    rows: list[dict] = []

    for repo in results:
        commit = repo.sbom.commit if repo.sbom else None

        for f in repo.findings:
            rows.append(_finding_row(
                repo=repo.name, tool="codeql", category="code",
                vuln_id=f.rule_id, cwe=f.cwe, title=f.rule_name,
                severity=_codeql_severity(f.security_severity, f.severity),
                severity_score=f.security_severity,
                file=f.file, start_line=f.start_line, end_line=f.end_line,
                message=f.message, commit=commit, detected_at=detected_at,
            ))

        grype = grype_by_repo.get(f"{organization}/{repo.name}")
        if grype and grype.report_path:
            for m in iter_matches(Path(grype.report_path)):
                rows.append(_finding_row(
                    repo=repo.name, tool="grype", category="dependency",
                    vuln_id=m["vuln_id"], cwe=[],
                    title=f"{m['package']} {m['version']}: {m['vuln_id']}",
                    severity=_grype_severity(m["severity"]),
                    severity_score=m["score"],
                    file=m["paths"][0] if m["paths"] else None,
                    package=m["package"], version=m["version"],
                    ecosystem=m["ecosystem"], fix_versions=m["fix_versions"],
                    commit=commit, detected_at=detected_at,
                ))

    rows.sort(key=lambda r: (
        r["repo"], r["tool"], r["file"] or "", r["start_line"] or 0, r["vuln_id"] or ""
    ))
    return rows


def build_repositories(
    organization: str,
    results: list[RepositoryResult],
    grype_results: list[GrypeResult],
    meta: dict[str, GitHubRepo],
) -> list[dict]:
    grype_by_repo = {g.full_name: g for g in grype_results}
    rows: list[dict] = []
    for repo in sorted(results, key=lambda r: r.name):
        full_name = f"{organization}/{repo.name}"
        grype = grype_by_repo.get(full_name)
        gh = meta.get(repo.name)
        rows.append({
            "repo": repo.name,
            "full_name": full_name,
            "url": repo.url,
            "status": repo.status.value,
            "languages": repo.languages,
            "primary_language": gh.language if gh else None,
            "stars": gh.stargazers_count if gh else None,
            "forks": gh.forks_count if gh else None,
            "size_kb": gh.size if gh else None,
            "pushed_at": gh.pushed_at if gh else None,
            "commit": repo.sbom.commit if repo.sbom else None,
            "sbom_status": repo.sbom.status.value if repo.sbom else None,
            "sbom_components": repo.sbom.components if repo.sbom else 0,
            "codeql_findings": len(repo.findings),
            "grype_status": grype.status.value if grype else None,
            "grype_vulnerabilities": grype.vulnerabilities if grype else 0,
            "error_message": repo.error_message,
        })
    return rows


def write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    return count