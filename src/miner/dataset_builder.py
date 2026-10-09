"""Integra los resultados de CodeQL (results.json) y Grype en datasets unificados.

Salidas en data/processed/:
  - dataset.csv / dataset.json : una fila por hallazgo (CodeQL y Grype)
  - repositories.csv           : una fila por repositorio (incluye repos sin hallazgos)
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterator

COLUMNS = [
    "source", "repository", "vulnerability_id", "title", "severity",
    "location", "start_line", "package", "package_version", "fix_versions",
]

REPO_COLUMNS = [
    "repository", "url", "status", "languages", "codeql_findings",
    "sbom_components", "grype_status", "grype_vulnerabilities",
    "grype_critical", "grype_high", "grype_medium", "grype_low",
    "grype_negligible", "grype_unknown",
]


def _row(**kwargs) -> dict:
    return {col: kwargs.get(col, "") for col in COLUMNS}


def _full_name(org: str, name: str) -> str:
    return name if "/" in name or not org else f"{org}/{name}"


def _codeql_rows(scan_report: dict) -> Iterator[dict]:
    org = scan_report.get("organization", "")
    for repo in scan_report.get("repositories", []):
        full_name = _full_name(org, repo["name"])
        for f in repo.get("findings", []):
            yield _row(
                source="codeql",
                repository=full_name,
                vulnerability_id=f["rule_id"],
                title=f.get("message", ""),
                severity=f.get("severity", ""),
                location=f.get("file", ""),
                start_line=f.get("start_line", ""),
            )


def _grype_rows(grype_report: dict) -> Iterator[dict]:
    for repo in grype_report.get("repositories", []):
        path = repo.get("report_path")
        if not path or not Path(path).exists():
            continue
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for match in data.get("matches", []):
            vuln = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            locations = artifact.get("locations") or []
            fix = (vuln.get("fix") or {}).get("versions") or []
            yield _row(
                source="grype",
                repository=repo["full_name"],
                vulnerability_id=vuln.get("id", ""),
                title=vuln.get("description", ""),
                severity=vuln.get("severity", ""),
                location=locations[0].get("path", "") if locations else "",
                package=artifact.get("name", ""),
                package_version=artifact.get("version", ""),
                fix_versions=",".join(fix),
            )


def _repository_rows(scan_report: dict | None, grype_report: dict | None) -> list[dict]:
    """Inventario por repositorio: incluye repos sin hallazgos (ceros reales)."""
    repos: dict[str, dict] = {}
    if scan_report:
        org = scan_report.get("organization", "")
        for r in scan_report.get("repositories", []):
            name = _full_name(org, r["name"])
            sbom = r.get("sbom") or {}
            repos[name] = {
                "repository": name,
                "url": r.get("url", ""),
                "status": r.get("status", ""),
                "languages": ";".join(r.get("languages", [])),
                "codeql_findings": len(r.get("findings", [])),
                "sbom_components": sbom.get("components", ""),
            }
    if grype_report:
        for g in grype_report.get("repositories", []):
            row = repos.setdefault(g["full_name"], {"repository": g["full_name"]})
            counts = {k.lower(): v for k, v in (g.get("severity_counts") or {}).items()}
            row["grype_status"] = g.get("status", "")
            row["grype_vulnerabilities"] = g.get("vulnerabilities", 0)
            for sev in ("critical", "high", "medium", "low", "negligible", "unknown"):
                row[f"grype_{sev}"] = counts.get(sev, 0)
    return [{c: r.get(c, "") for c in REPO_COLUMNS} for r in sorted(repos.values(), key=lambda x: x["repository"])]


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def build_dataset(
    scan_json: Path | None,
    grype_json: Path | None,
    out_dir: Path = Path("data/processed"),
) -> list[dict]:
    """Construye dataset.csv/json (hallazgos) y repositories.csv (inventario)."""
    scan = json.loads(Path(scan_json).read_text(encoding="utf-8")) if scan_json else None
    grype = json.loads(Path(grype_json).read_text(encoding="utf-8")) if grype_json else None

    rows: list[dict] = []
    if scan:
        rows += list(_codeql_rows(scan))
    if grype:
        rows += list(_grype_rows(grype))

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(out_dir / "dataset.csv", COLUMNS, rows)
    (out_dir / "dataset.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _write_csv(out_dir / "repositories.csv", REPO_COLUMNS, _repository_rows(scan, grype))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the unified vulnerability dataset")
    parser.add_argument("--scan", type=Path, default=Path("data/raw/results.json"))
    parser.add_argument("--grype", type=Path, default=Path("data/raw/grype/grype-report.json"))
    parser.add_argument("--out-dir", type=Path, default=Path("data/processed"))
    args = parser.parse_args()
    rows = build_dataset(
        args.scan if args.scan.exists() else None,
        args.grype if args.grype.exists() else None,
        args.out_dir,
    )
    print(f"{len(rows)} findings written to {args.out_dir} (+ repositories.csv)")


if __name__ == "__main__":
    main()
