"""Genera el reporte final en Markdown."""

from pathlib import Path


def write_report(content: str, output: Path = Path("reports/security_audit_report.md")) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    return output
