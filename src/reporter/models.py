"""Modelos de datos del Reporter (Pydantic v2).

Toda afirmación del reporte debe poder rastrearse hasta una :class:`EvidenceItem`
con archivo y línea observables. La interpretación del LLM nunca introduce
hallazgos nuevos: solo enriquece el resumen y las recomendaciones de hallazgos
que ya existen (ver ``llm_client``).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severidad de un hallazgo, ordenada de mayor a menor riesgo."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Posición de orden (0 = más severo) para un ordenamiento estable."""
        return _SEVERITY_RANK[self.value]


_SEVERITY_RANK = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


class EvidenceItem(BaseModel):
    """Observación concreta y verificable extraída del repositorio."""

    evidence_id: str
    aspect: str
    file: str
    start_line: int
    end_line: Optional[int] = None
    snippet: str
    snippet_sha256: str
    rule: str
    source: str = "inspector"


class Finding(BaseModel):
    """Problema potencial agrupado, siempre respaldado por evidencia."""

    finding_id: str
    aspect: str
    severity: Severity
    title: str
    description: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: str = "high"
    remediation: str = ""


class InspectionResult(BaseModel):
    """Resultado determinista del inspector, apto para serializar."""

    repo_root: str
    inspector_version: str
    generated_at: datetime
    files_scanned: int
    aspects: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    def to_ordered_json(self) -> dict:
        """Representación JSON con orden estable (para prompts y diff)."""
        return {
            "repo_root": self.repo_root,
            "inspector_version": self.inspector_version,
            "generated_at": self.generated_at.isoformat(),
            "files_scanned": self.files_scanned,
            "aspects": list(self.aspects),
            "evidence": [e.model_dump(mode="json") for e in self.evidence],
            "findings": [f.model_dump(mode="json") for f in self.findings],
        }


class LLMAnalysis(BaseModel):
    """Salida del LLM (o del fallback determinista)."""

    summary: str = ""
    recommendations: dict[str, str] = Field(default_factory=dict)
    used_fallback: bool = True
    model: str = ""
    error: Optional[str] = None
