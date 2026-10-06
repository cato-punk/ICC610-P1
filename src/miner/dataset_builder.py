"""Integra los resultados de CodeQL (results.json) y Grype en un dataset unificado.

Una fila por hallazgo, con columnas comunes para ambas fuentes.
Salida: data/processed/dataset.csv y data/processed/dataset.json
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


def _row(**kwargs) -> dict:
    return {col: kwargs.get(col, "") for col in COLUMNS}


def _codeql_rows(scan_report: dict) -> Iterator[dict]:
    org = scan_report.get("organization", "")
    for repo in scan_report.get("repositories", []):
        name = repo["name"]
        full_name = name if "/" in name or not org else f"{org}/{name}"
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


def build_dataset(
    scan_json: Path | None,
    grype_json: Path | None,
    out_dir: Path = Path("data/processed"),
) -> list[dict]:
    """Construye el dataset unificado y lo escribe en CSV y JSON."""
    rows: list[dict] = []
    if scan_json:
        rows += list(_codeql_rows(json.loads(Path(scan_json).read_text(encoding="utf-8"))))
    if grype_json:
        rows += list(_grype_rows(json.loads(Path(grype_json).read_text(encoding="utf-8"))))

    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "dataset.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "dataset.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the unified vulnerability dataset")
    parser.add_argument("--scan", type=Path, default=Path("data/raw/results.json"))
    parser.add_argument("--grype", type=Path, help="JSON report produced by `miner grype`")
    parser.add_argument("--out-dir", type=Path, default=Path("data/processed"))
    args = parser.parse_args()
    rows = build_dataset(args.scan if args.scan.exists() else None, args.grype, args.out_dir)
    print(f"{len(rows)} rows written to {args.out_dir}")


if __name__ == "__main__":
    main()
