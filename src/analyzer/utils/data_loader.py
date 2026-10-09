"""Carga y normalización de los datasets generados por el Miner (data/processed/)."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

GRYPE_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
# SARIF level de CodeQL -> nivel comparable. Es una convención, no una medida exacta.
CODEQL_LEVEL_MAP = {"error": "High", "warning": "Medium", "note": "Low", "recommendation": "Low"}


def project_root(start: Path | None = None) -> Path:
    """Sube desde `start` (o el cwd) hasta encontrar pyproject.toml."""
    current = (start or Path.cwd()).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "pyproject.toml").exists():
            return candidate
    raise FileNotFoundError("No se encontró pyproject.toml; ejecuta desde dentro del repositorio.")


def processed_dir() -> Path:
    return project_root() / "data" / "processed"


def analysis_dir() -> Path:
    path = processed_dir() / "analysis"
    path.mkdir(parents=True, exist_ok=True)
    return path


def classify_path(path: str) -> str:
    """Clasifica una ruta de archivo: tests, docs, examples o source."""
    p = str(path).lower().replace("\\", "/")
    parts = p.split("/")
    if any(x in ("tests", "test", "testing") for x in parts) or Path(p).name.startswith("test_"):
        return "tests"
    if any(x in ("docs", "doc", "documentation") for x in parts):
        return "docs"
    if any(x in ("examples", "example", "demo", "docs_src") for x in parts):
        return "examples"
    return "source"


def load_dataset() -> pd.DataFrame:
    df = pd.read_csv(processed_dir() / "dataset.csv", keep_default_na=False)
    df["start_line"] = pd.to_numeric(df["start_line"], errors="coerce")
    df["fixable"] = df["fix_versions"].astype(str).str.len() > 0
    df["severity_level"] = df["severity"]
    is_codeql = df["source"] == "codeql"
    df.loc[is_codeql, "severity_level"] = (
        df.loc[is_codeql, "severity"].str.lower().map(CODEQL_LEVEL_MAP).fillna("Unknown")
    )
    df["severity_level"] = df["severity_level"].str.capitalize()
    df["path_category"] = df["location"].map(classify_path)
    return df


def load_repositories() -> pd.DataFrame:
    df = pd.read_csv(processed_dir() / "repositories.csv", keep_default_na=False)
    numeric = [c for c in df.columns if c.startswith("grype_") and c != "grype_status"]
    numeric += ["codeql_findings", "sbom_components"]
    for col in numeric:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df["short_name"] = df["repository"].str.split("/").str[-1]
    return df
