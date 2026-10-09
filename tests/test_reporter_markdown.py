"""Pruebas del generador de Markdown del Reporter."""

from __future__ import annotations

from datetime import datetime, timezone

from reporter.markdown_generator import render, write_report
from reporter.models import InspectionResult, LLMAnalysis
from reporter.repo_inspector import collect_evidence


def test_render_fallback_banner(sample_repo):
    result = collect_evidence(sample_repo)
    md = render(result, LLMAnalysis(used_fallback=True, error="sin clave"))
    assert "# Auditoría de seguridad del repositorio" in md
    assert "Reporte determinista" in md
    assert "sin clave" in md


def test_render_contains_evidence_locations(sample_repo):
    result = collect_evidence(sample_repo)
    md = render(result, None)
    assert "`.github/workflows/ci.yml:" in md
    assert "## Apéndice: evidencia" in md


def test_render_redacts_secret(sample_repo):
    result = collect_evidence(sample_repo)
    md = render(result, None)
    assert "sk-1234567890abcdef1234" not in md
    assert "[REDACTED]" in md


def test_render_uses_llm_summary_and_recommendation(sample_repo):
    result = collect_evidence(sample_repo)
    finding_id = result.findings[0].finding_id
    analysis = LLMAnalysis(
        used_fallback=False,
        summary="Resumen del modelo",
        model="gpt-test",
        recommendations={finding_id: "RECOMENDACION-LLM"},
    )
    md = render(result, analysis)
    assert "Resumen del modelo" in md
    assert "RECOMENDACION-LLM" in md
    assert "gpt-test" in md


def test_render_no_findings():
    result = InspectionResult(
        repo_root="/tmp/x",
        inspector_version="0.1.0",
        generated_at=datetime.now(timezone.utc),
        files_scanned=0,
        aspects=[],
        evidence=[],
        findings=[],
    )
    md = render(result, None)
    assert "No se encontraron hallazgos" in md


def test_render_skips_missing_evidence(sample_repo):
    from reporter.models import Finding, Severity

    result = collect_evidence(sample_repo)
    result.findings.append(
        Finding(
            finding_id="aspecto-x:regla-y",
            aspect="aspecto-x",
            severity=Severity.LOW,
            title="hallazgo sin evidencia resoluble",
            description="descripción",
            evidence_ids=["evidencia-inexistente"],
        )
    )
    md = render(result, None)
    assert "aspecto-x:regla-y" in md


def test_write_report(tmp_path):
    path = write_report("contenido", tmp_path / "sub" / "r.md")
    assert path.exists()
    assert path.read_text(encoding="utf-8") == "contenido"
