"""Carga y normalización de los datos de `data/processed/` para el Visualizer."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pandas as pd

# Espejo de analyzer.utils.data_loader.GRYPE_SEVERITY_ORDER.
GRYPE_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

# Espejo de analyzer.utils.data_loader.CODEQL_LEVEL_MAP.
CODEQL_LEVEL_MAP = {"error": "High", "warning": "Medium", "note": "Low", "recommendation": "Low"}

# Espejo de miner.dataset_builder.COLUMNS (una fila por hallazgo).
FINDINGS_COLUMNS = [
    "source",
    "repository",
    "vulnerability_id",
    "title",
    "severity",
    "location",
    "start_line",
    "package",
    "package_version",
    "fix_versions",
]

# Espejo de miner.dataset_builder.REPO_COLUMNS (una fila por repositorio).
REPOSITORY_COLUMNS = [
    "repository",
    "url",
    "status",
    "languages",
    "codeql_findings",
    "sbom_components",
    "grype_status",
    "grype_vulnerabilities",
    "grype_critical",
    "grype_high",
    "grype_medium",
    "grype_low",
    "grype_negligible",
    "grype_unknown",
]

# Columnas de repositories.csv que son texto y no deben convertirse a numérico.
REPOSITORIES_TEXT_COLUMNS = {"repository", "url", "status", "languages", "grype_status"}

# Exportaciones del Analyzer en data/processed/analysis/:
ANALYSIS_CSVS: dict[str, tuple[list[str], set[str]]] = {
    "severity_overview": (["source"], {"source"}),
    "codeql_rules": (["vulnerability_id", "findings", "repos"], {"vulnerability_id"}),
    "codeql_path_categories": (["path_category"], {"path_category"}),
    "grype_severity": (
        ["severity_level", "matches", "distinct_cves", "fixable_share"],
        {"severity_level"},
    ),
    "grype_top_packages": (
        [
            "package",
            "package_version",
            "matches",
            "distinct_cves",
            "repos",
            "worst",
            "fixable",
        ],
        {"package", "package_version", "worst"},
    ),
    "repo_risk_ranking": (
        [
            "repository",
            "short_name",
            "status",
            "sbom_components",
            "score_deps",
            "score_code",
            "score_total",
        ],
        {"repository", "short_name", "status"},
    ),
}


def project_root() -> Path:
    """Raíz del repositorio: sube desde este archivo hasta encontrar `pyproject.toml`."""
    start = Path(__file__).resolve().parent
    for candidate in [start, *start.parents]:
        if (candidate / "pyproject.toml").exists():
            return candidate
    raise FileNotFoundError(
        "No se encontró pyproject.toml desde src/visualizer; "
        "¿se instaló el proyecto en modo editable (pip install -e)?"
    )


def processed_dir() -> Path:
    """Directorio `data/processed/` (solo lectura; no lo crea)."""
    return project_root() / "data" / "processed"


def analysis_dir() -> Path:
    """Directorio `data/processed/analysis/` (solo lectura; no lo crea)."""
    return processed_dir() / "analysis"


def classify_path(path: str) -> str:
    """Clasifica una ruta de archivo: tests, docs, examples o source.

    Espejo de analyzer.utils.data_loader.classify_path.
    """
    p = str(path).lower().replace("\\", "/")
    parts = p.split("/")
    if any(x in ("tests", "test", "testing") for x in parts) or Path(p).name.startswith("test_"):
        return "tests"
    if any(x in ("docs", "doc", "documentation") for x in parts):
        return "docs"
    if any(x in ("examples", "example", "demo", "docs_src") for x in parts):
        return "examples"
    return "source"


def _read_csv(
    path: Path,
    required_columns: list[str],
    label: str,
    missing: list[str],
) -> pd.DataFrame:
    """Lee un CSV; si falta, falla o no tiene las columnas requeridas, lo registra
    en `missing` y devuelve un DataFrame vacío con `required_columns`."""
    if not path.exists():
        missing.append(label)
        return pd.DataFrame(columns=required_columns)
    try:
        df = pd.read_csv(path, keep_default_na=False)
    except Exception:
        missing.append(label)
        return pd.DataFrame(columns=required_columns)
    absent = [c for c in required_columns if c not in df.columns]
    if absent:
        missing.append(f"{label} (faltan columnas: {', '.join(absent)})")
        return pd.DataFrame(columns=required_columns)
    return df


def _read_summary(path: Path, label: str, missing: list[str]) -> dict:
    """Lee summary.json; si falta o no es un objeto JSON, lo registra y devuelve {}."""
    if not path.exists():
        missing.append(label)
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        missing.append(label)
        return {}
    if not isinstance(data, dict):
        missing.append(label)
        return {}
    return data


def _coerce_numeric(df: pd.DataFrame, text_columns: set[str]) -> pd.DataFrame:
    """Convierte a numérico todas las columnas salvo las de texto indicadas."""
    for col in df.columns:
        if col in text_columns:
            continue
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def normalize_findings(df: pd.DataFrame) -> pd.DataFrame:
    """Deriva las columnas que necesita la interfaz a partir de `dataset.csv`"""
    df = df.copy()
    if "start_line" in df.columns:
        df["start_line"] = pd.to_numeric(df["start_line"], errors="coerce")
    if df.empty:
        for col in ("fixable", "severity_level", "path_category"):
            if col not in df.columns:
                df[col] = pd.Series(index=df.index, dtype="object")
        return df
    df["fixable"] = df["fix_versions"].astype(str).str.len() > 0
    df["severity_level"] = df["severity"]
    is_codeql = df["source"] == "codeql"
    df.loc[is_codeql, "severity_level"] = (
        df.loc[is_codeql, "severity"].str.lower().map(CODEQL_LEVEL_MAP).fillna("Unknown")
    )
    df["severity_level"] = df["severity_level"].str.capitalize()
    df["path_category"] = df["location"].map(classify_path)
    return df


def derive_org(repositories: pd.DataFrame) -> str:
    """Organización más frecuente (prefijo antes de la primera `/`) de los repos."""
    if repositories.empty or "repository" not in repositories.columns:
        return ""
    prefixes = Counter(
        str(name).split("/", 1)[0] for name in repositories["repository"] if "/" in str(name)
    )
    return prefixes.most_common(1)[0][0] if prefixes else ""


def load_all() -> dict[str, object]:
    """Lee todo `data/processed/` y devuelve el paquete de datos de la UI."""
    processed = processed_dir()
    analysis = processed / "analysis"
    missing: list[str] = []

    summary = _read_summary(analysis / "summary.json", "analysis/summary.json", missing)

    frames: dict[str, pd.DataFrame] = {}
    for name, (required, text_columns) in ANALYSIS_CSVS.items():
        df = _read_csv(analysis / f"{name}.csv", required, f"analysis/{name}.csv", missing)
        frames[name] = _coerce_numeric(df, text_columns)

    repositories = _read_csv(
        processed / "repositories.csv", REPOSITORY_COLUMNS, "repositories.csv", missing
    )
    repositories = _coerce_numeric(repositories, REPOSITORIES_TEXT_COLUMNS | {"short_name"})
    repositories["short_name"] = repositories["repository"].str.split("/").str[-1]

    findings = _read_csv(processed / "dataset.csv", FINDINGS_COLUMNS, "dataset.csv", missing)
    findings = normalize_findings(findings)

    return {
        "summary": summary,
        **frames,
        "repositories": repositories,
        "findings": findings,
        "missing": missing,
        "org": derive_org(repositories),
    }
