"""Punto de entrada del Reporter: `python -m reporter.cli`."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from . import llm_client, markdown_generator, repo_inspector
from . import state as state_mod
from .models import InspectionResult, Severity

app = typer.Typer(
    add_completion=False,
    help="Audita la seguridad de este repositorio y genera un reporte Markdown.",
)

FAIL_LEVELS: dict[str, set[Severity]] = {
    "critical": {Severity.CRITICAL},
    "high": {Severity.CRITICAL, Severity.HIGH},
}


def _should_fail(result: InspectionResult, fail_on: str) -> bool:
    levels = FAIL_LEVELS.get(fail_on)
    if not levels:
        return False
    return any(finding.severity in levels for finding in result.findings)


@app.command()
def audit(
    repo_root: Path = typer.Option(
        Path.cwd(), "--repo-root", "-r", help="Raíz del repositorio a auditar."
    ),
    output: Path = typer.Option(
        markdown_generator.DEFAULT_OUTPUT,
        "--output",
        "-o",
        help="Ruta del reporte Markdown de salida.",
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Genera el reporte en modo determinista, sin LLM."
    ),
    strict_llm: bool = typer.Option(
        False,
        "--strict-llm",
        help="Falla (código 2) si el LLM no está disponible.",
    ),
    model: Optional[str] = typer.Option(
        None, "--model", help="Modelo a usar (sobrescribe LLM_MODEL)."
    ),
    fail_on: str = typer.Option(
        "never",
        "--fail-on",
        help="Falla (código 1) si hay hallazgos de severidad: never|critical|high.",
    ),
    rotate_aspects: bool = typer.Option(
        False,
        "--rotate-aspects",
        help="Selecciona 4 aspectos con la estrategia 60/40 (uso programado).",
    ),
    state_file: Path = typer.Option(
        state_mod.DEFAULT_STATE_FILE,
        "--state-file",
        help="Archivo de estado para la rotación de aspectos.",
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Oculta el resumen por consola."),
) -> None:
    """Ejecuta el inspector, opcionalmente el LLM, y escribe el reporte."""
    if fail_on not in {"never", "critical", "high"}:
        typer.echo(f"Error: --fail-on inválido: {fail_on!r}.", err=True)
        raise typer.Exit(2)

    aspects = list(repo_inspector.ASPECTS)
    state: Optional[dict] = None
    if rotate_aspects:
        state = state_mod.load_state(state_file)
        aspects, state = state_mod.select_aspects(state, repo_inspector.ASPECTS)

    result = repo_inspector.collect_evidence(repo_root, aspects=aspects)
    analysis = llm_client.analyze(result, use_llm=not no_llm, model=model)

    if strict_llm and analysis.used_fallback:
        typer.echo(
            f"Error: el LLM no está disponible ({analysis.error}).", err=True
        )
        raise typer.Exit(2)

    content = markdown_generator.render(result, analysis)
    path = markdown_generator.write_report(content, output)

    if rotate_aspects and state is not None:
        state_mod.save_state(state, state_file)

    if not quiet:
        typer.echo(f"Reporte escrito en {path}")
        typer.echo(
            f"Archivos inspeccionados: {result.files_scanned} · "
            f"Hallazgos: {len(result.findings)}"
        )
        if analysis.used_fallback:
            typer.echo(f"Modo determinista (LLM no usado): {analysis.error}")

    if _should_fail(result, fail_on):
        typer.echo(
            f"Se encontraron hallazgos de severidad >= {fail_on}.", err=True
        )
        raise typer.Exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
