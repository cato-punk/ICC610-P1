"""Recolecta evidencia de seguridad del repositorio local."""

from pathlib import Path


def collect_evidence(repo_root: Path) -> dict:
    """Inspecciona código, dependencias, configuraciones y workflows.

    Cada hallazgo debe llevar archivo y línea para mantener trazabilidad
    (la especificación prohíbe afirmar problemas sin evidencia observable).
    """
    raise NotImplementedError
