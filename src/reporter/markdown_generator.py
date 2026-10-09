"""Genera el reporte final en Markdown.

El esqueleto, las tablas y la evidencia se construyen de forma determinista a
partir de :class:`InspectionResult`. El LLM solo aporta el resumen ejecutivo y
las recomendaciones por hallazgo; si no está disponible, se usa un texto
determinista con un aviso visible (mecanismo de fallback).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .models import InspectionResult, LLMAnalysis, Severity

DEFAULT_OUTPUT = Path("reports/security_audit_report.md")

_SEVERITY_LABEL = {
    Severity.CRITICAL: "🔴 Crítica",
    Severity.HIGH: "🟠 Alta",
    Severity.MEDIUM: "🟡 Media",
    Severity.LOW: "🔵 Baja",
    Severity.INFO: "⚪ Informativa",
}


def _escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _deterministic_summary(result: InspectionResult) -> str:
    if not result.findings:
        return (
            "El inspector no encontró hallazgos respaldados por evidencia en los "
            "aspectos evaluados."
        )
    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    breakdown = ", ".join(f"{sev}: {counts[sev]}" for sev in order if sev in counts)
    return (
        f"Se identificaron {len(result.findings)} hallazgos respaldados por "
        f"evidencia ({breakdown}). Cada uno referencia archivo y línea; los "
        "detalles y las recomendaciones aparecen a continuación."
    )


def _render_finding(result: InspectionResult, finding, analysis: Optional[LLMAnalysis]) -> str:
    by_id = {e.evidence_id: e for e in result.evidence}
    lines: list[str] = []
    label = _SEVERITY_LABEL.get(finding.severity, finding.severity.value)
    lines.append(f"#### {label} — {finding.title}")
    lines.append("")
    lines.append(f"- **Aspecto:** `{finding.aspect}`")
    lines.append(f"- **ID:** `{finding.finding_id}`")
    lines.append(f"- **Confianza:** {finding.confidence}")
    lines.append("")
    lines.append(finding.description)
    lines.append("")
    lines.append("**Evidencia:**")
    lines.append("")
    for evidence_id in finding.evidence_ids:
        item = by_id.get(evidence_id)
        if item is None:
            continue
        location = f"`{item.file}:{item.start_line}`"
        lines.append(f"- {location} — regla `{item.rule}`")
        lines.append("")
        lines.append("<details><summary>Fragmento</summary>")
        lines.append("")
        lines.append("```")
        lines.append(item.snippet)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    recommendation = ""
    if analysis is not None and finding.finding_id in analysis.recommendations:
        recommendation = analysis.recommendations[finding.finding_id]
    if not recommendation:
        recommendation = finding.remediation
    if recommendation:
        lines.append(f"**Recomendación:** {recommendation}")
        lines.append("")

    return "\n".join(lines)


def render(result: InspectionResult, analysis: Optional[LLMAnalysis] = None) -> str:
    """Renderiza el reporte completo en Markdown."""
    used_fallback = analysis is None or analysis.used_fallback
    summary = (analysis.summary if analysis and analysis.summary else "").strip()
    if not summary:
        summary = _deterministic_summary(result)

    parts: list[str] = []
    parts.append("# Auditoría de seguridad del repositorio")
    parts.append("")
    parts.append(
        f"> Generado por el Reporter (inspector `{result.inspector_version}`) el "
        f"{result.generated_at.isoformat()}."
    )
    parts.append(
        f"> Raíz analizada: `{result.repo_root}` · Archivos inspeccionados: "
        f"{result.files_scanned} · Aspectos: {', '.join(result.aspects)}."
    )
    if used_fallback:
        reason = analysis.error if analysis and analysis.error else "no disponible"
        parts.append(
            f"> ⚠️ **Reporte determinista (fallback):** el LLM no se utilizó "
            f"({reason}). El contenido no depende del modelo."
        )
    else:
        parts.append(f"> Modelo utilizado: `{analysis.model}`.")
    parts.append("")

    parts.append("## Resumen ejecutivo")
    parts.append("")
    parts.append(summary)
    parts.append("")

    parts.append("## Alcance y método")
    parts.append("")
    parts.append(
        "El inspector recorre el repositorio de forma determinista y aplica "
        "reglas basadas en patrones observables sobre código, dependencias, "
        "configuración y workflows. Cada afirmación se respalda con la evidencia "
        "listada (archivo, línea y fragmento). No se ejecuta código del "
        "repositorio."
    )
    parts.append("")

    parts.append("## Hallazgos")
    parts.append("")
    if not result.findings:
        parts.append("No se encontraron hallazgos respaldados por evidencia.")
        parts.append("")
    else:
        parts.append("| Severidad | Aspecto | Hallazgo | Evidencia |")
        parts.append("|---|---|---|---|")
        by_id = {e.evidence_id: e for e in result.evidence}
        for finding in result.findings:
            locations = []
            for evidence_id in finding.evidence_ids:
                item = by_id.get(evidence_id)
                if item is not None:
                    locations.append(f"`{item.file}:{item.start_line}`")
            location_text = ", ".join(locations) if locations else "—"
            label = _SEVERITY_LABEL.get(finding.severity, finding.severity.value)
            parts.append(
                f"| {label} | `{finding.aspect}` | {_escape_cell(finding.title)} | "
                f"{location_text} |"
            )
        parts.append("")
        parts.append("### Detalle")
        parts.append("")
        for finding in result.findings:
            parts.append(_render_finding(result, finding, analysis))

    parts.append("## Limitaciones")
    parts.append("")
    parts.append(
        "El análisis es heurístico y se basa en lo que es observable en los "
        "archivos del repositorio; no sustituye una revisión manual ni un "
        "escáner dedicado. Los hallazgos son indicios respaldados por evidencia, "
        "no confirmaciones de explotabilidad."
    )
    parts.append("")

    parts.append("## Apéndice: evidencia")
    parts.append("")
    if result.evidence:
        parts.append("| ID | Aspecto | Archivo:línea | Fragmento |")
        parts.append("|---|---|---|---|")
        for item in result.evidence:
            parts.append(
                f"| `{item.evidence_id}` | `{item.aspect}` | "
                f"`{item.file}:{item.start_line}` | `{_escape_cell(item.snippet)}` |"
            )
        parts.append("")

    return "\n".join(parts)


def write_report(
    content: str, output: Path = DEFAULT_OUTPUT
) -> Path:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    return output
