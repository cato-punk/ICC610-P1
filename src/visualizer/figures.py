"""Constructores de figuras Plotly para el Visualizer."""

from __future__ import annotations

import pandas as pd
from plotly import graph_objects as go

NA = "—"

SEVERIDAD_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
SEVERIDAD_COLOR = {
    "Critical": "#7f1d1d",
    "High": "#dc2626",
    "Medium": "#f59e0b",
    "Low": "#65a30d",
    "Negligible": "#94a3b8",
    "Unknown": "#cbd5e1",
}
COLOR_GRYPE = "#dc2626"
COLOR_CODEQL = "#2563eb"
COLOR_SBOM = "#0891b2"
COLOR_RISK = "#475569"

METRICA_LABELS = {
    "grype_vulnerabilities": "Vulnerabilidades Grype",
    "codeql_findings": "Hallazgos CodeQL",
    "sbom_components": "Componentes del SBOM (Syft)",
    "score_total": "Puntaje de riesgo total",
}
METRICA_COLOR = {
    "grype_vulnerabilities": COLOR_GRYPE,
    "codeql_findings": COLOR_CODEQL,
    "sbom_components": COLOR_SBOM,
    "score_total": COLOR_RISK,
}



def _int(valor) -> str:
    """Entero con separador de miles (punto). `None`/no numérico -> «—»."""
    try:
        return f"{round(float(valor)):,.0f}".replace(",", ".")
    except (TypeError, ValueError):
        return NA


def _pct_local(valor, decimals: int = 1) -> str:
    """Fracción -> porcentaje localizado con coma decimal: 0.565 -> «56,5 %»."""
    if valor is None:
        return NA
    try:
        pct = float(valor) * 100.0
    except (TypeError, ValueError):
        return NA
    redondeado = round(pct, decimals)
    if redondeado == int(redondeado):
        return f"{int(redondeado)} %"
    return f"{pct:.{decimals}f}".replace(".", ",") + " %"


def _num_local(valor, decimals: int = 2) -> str:
    """Número localizado con coma decimal: 0.73 -> «0,73»."""
    if valor is None:
        return NA
    try:
        return f"{float(valor):.{decimals}f}".replace(".", ",")
    except (TypeError, ValueError):
        return NA


def _config(
    fig: go.Figure,
    titulo: str,
    x_titulo: str = "",
    y_titulo: str = "",
    altura: int = 520,
) -> go.Figure:
    """Estilo común: plantilla local (sin red), títulos en español."""
    fig.update_layout(
        title=dict(text=titulo, x=0.02, xanchor="left"),
        template="plotly_white",
        height=altura,
        margin=dict(t=80, b=50, l=12, r=12),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
    )
    if x_titulo:
        fig.update_xaxes(title_text=x_titulo)
    if y_titulo:
        fig.update_yaxes(title_text=y_titulo)
    return fig


def _fig_vacia(titulo: str, fuente: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=f"Sin datos para esta vista (falta {fuente}).",
        x=0.5,
        y=0.5,
        xref="paper",
        yref="paper",
        showarrow=False,
        font=dict(color="#64748b"),
    )
    return _config(fig, titulo)


def texto_codeql_source(summary: dict | None) -> str:
    summary = summary or {}
    share = summary.get("codeql_source_share")
    if share is None:
        return ""
    return (
        f"Solo el {_pct_local(share)} de los hallazgos de CodeQL está en código "
        "fuente; el resto está en tests, docs o ejemplos."
    )


def texto_concentracion(summary: dict | None, metrica: str) -> str:
    summary = summary or {}
    clave = {"codeql_findings": "CodeQL", "grype_vulnerabilities": "Grype"}.get(metrica)
    if not clave:
        return ""
    conc = (summary.get("concentration") or {}).get(clave) or {}
    if conc.get("top3_share") is None:
        return ""
    return (
        f"{clave}: los 3 repositorios de mayor nivel concentran "
        f"{_pct_local(conc['top3_share'])} del total "
        f"(Gini {_num_local(conc.get('gini'))})."
    )


def fig_severidad_overview(df: pd.DataFrame) -> go.Figure:
    """Barras horizontales apiladas source (codeql/grype) × severidad."""
    titulo = "Severidad comparada por herramienta"
    if df.empty or "source" not in df.columns:
        return _fig_vacia(titulo, "analysis/severity_overview.csv")
    columnas_sev = [c for c in SEVERIDAD_ORDER if c in df.columns]
    if not columnas_sev:
        return _fig_vacia(titulo, "analysis/severity_overview.csv (columnas de severidad)")
    etiquetas = {"codeql": "CodeQL", "grype": "Grype"}
    df = df.copy()
    fuentes = df["source"].map(etiquetas).fillna(df["source"].astype(str))
    fig = go.Figure()
    for col in columnas_sev:
        valores = pd.to_numeric(df[col], errors="coerce").fillna(0)
        fig.add_trace(
            go.Bar(
                y=fuentes,
                x=valores,
                name=col,
                orientation="h",
                marker_color=SEVERIDAD_COLOR.get(col, SEVERIDAD_COLOR["Unknown"]),
                text=[_int(v) if v else None for v in valores],
                textposition="inside",
                hovertemplate=f"%{{y}} — {col}: %{{x}}<extra></extra>",
            )
        )
    fig.update_layout(barmode="stack")
    return _config(fig, titulo, x_titulo="Hallazgos y coincidencias")



def fig_repositorios(
    repositories: pd.DataFrame,
    risk_ranking: pd.DataFrame,
    summary: dict | None,
    metrica: str = "grype_vulnerabilities",
    top_n: int = 10,
) -> go.Figure:
    """Barras por repositorio (incluye ceros), orden descendente, Top-N."""
    summary = summary or {}
    titulo = f"Repositorios por métrica: {METRICA_LABELS.get(metrica, metrica)}"
    if repositories.empty or "repository" not in repositories.columns:
        return _fig_vacia(titulo, "repositories.csv")
    df = repositories.copy()
    if metrica == "score_total":
        if risk_ranking.empty or not {"repository", "score_total"}.issubset(
            risk_ranking.columns
        ):
            return _fig_vacia(titulo, "analysis/repo_risk_ranking.csv")
        df = df.merge(
            risk_ranking[["repository", "score_total"]], on="repository", how="left"
        )
    if metrica not in df.columns:
        return _fig_vacia(titulo, "repositories.csv (falta la columna de la métrica)")
    df[metrica] = pd.to_numeric(df[metrica], errors="coerce").fillna(0)
    df = df.sort_values(metrica, ascending=False).reset_index(drop=True)
    if top_n and top_n > 0:
        df = df.head(int(top_n))
    if "short_name" not in df.columns:
        df["short_name"] = df["repository"].astype(str).str.split("/").str[-1]
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            y=df["short_name"],
            x=df[metrica],
            orientation="h",
            marker_color=METRICA_COLOR.get(metrica, COLOR_RISK),
            text=[_int(v) for v in df[metrica]],
            textposition="outside",
            hovertemplate="%{y}: %{x}<extra></extra>",
        )
    )
    return _config(fig, titulo, x_titulo=METRICA_LABELS.get(metrica, metrica))


def fig_relaciones(
    repositories: pd.DataFrame,
    summary: dict | None,
    pareja: str = "components",
) -> go.Figure:
    """Scatter entre métricas por repo con la correlación de Spearman."""
    summary = summary or {}
    if pareja == "codeql":
        x_metrica, spearman_key = "codeql_findings", "codeql_vs_grype"
        titulo = "Hallazgos CodeQL vs vulnerabilidades Grype"
        color = COLOR_CODEQL
    else:
        x_metrica, spearman_key = "sbom_components", "components_vs_grype"
        titulo = "Componentes del SBOM (Syft) vs vulnerabilidades Grype"
        color = COLOR_SBOM
    if repositories.empty or not {
        "repository",
        x_metrica,
        "grype_vulnerabilities",
    }.issubset(repositories.columns):
        return _fig_vacia(titulo, "repositories.csv")
    df = repositories.copy()
    x = pd.to_numeric(df[x_metrica], errors="coerce").fillna(0)
    y = pd.to_numeric(df["grype_vulnerabilities"], errors="coerce").fillna(0)
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=x,
            y=y,
            mode="markers",
            marker=dict(color=color, opacity=0.7, size=10),
            text=df["repository"],
            hovertemplate="<b>%{text}</b><br>%{x} vs %{y}<extra></extra>",
        )
    )
    spearman = (summary.get("spearman") or {}).get(spearman_key)
    if spearman is not None:
        fig.add_annotation(
            text=f"Correlación de Spearman: {_num_local(spearman)}",
            xref="paper",
            yref="paper",
            x=0.98,
            y=0.98,
            showarrow=False,
            font=dict(size=13),
            bgcolor="rgba(248,250,252,0.9)",
        )
    return _config(
        fig,
        titulo,
        x_titulo=METRICA_LABELS.get(x_metrica, x_metrica),
        y_titulo="Vulnerabilidades Grype (por repositorio)",
        altura=380,
    )


def fig_codeql_reglas(df: pd.DataFrame) -> go.Figure:
    """Barras horizontales de las 10 reglas con más hallazgos y «N repos»."""
    titulo = "Reglas de CodeQL más frecuentes (top 10)"
    if df.empty or not {"vulnerability_id", "findings", "repos"}.issubset(df.columns):
        return _fig_vacia(titulo, "analysis/codeql_rules.csv")
    df = df.copy()
    df["findings"] = pd.to_numeric(df["findings"], errors="coerce").fillna(0)
    df = df.sort_values("findings", ascending=False).head(10)
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            y=df["vulnerability_id"],
            x=df["findings"],
            orientation="h",
            marker_color=COLOR_CODEQL,
            text=[f"{_int(r)} repos" for r in df["repos"]],
            textposition="outside",
            hovertemplate="%{y}: %{x} hallazgos<br>%{text}<extra></extra>",
        )
    )
    return _config(fig, titulo, x_titulo="Hallazgos")



def fig_codeql_categorias(df: pd.DataFrame) -> go.Figure:
    """Barras apiladas path_category (source/tests/docs/examples) × severidad."""
    titulo = "Hallazgos de CodeQL por categoría de ruta"
    if df.empty or "path_category" not in df.columns:
        return _fig_vacia(titulo, "analysis/codeql_path_categories.csv")
    columnas_sev = [c for c in SEVERIDAD_ORDER if c in df.columns]
    if not columnas_sev:
        return _fig_vacia(titulo, "analysis/codeql_path_categories.csv (severidad)")
    orden_categorias = ["source", "tests", "docs", "examples"]
    presentes = [c for c in orden_categorias if c in set(df["path_category"].astype(str))]
    y = presentes or list(df["path_category"].astype(str))
    fig = go.Figure()
    for col in columnas_sev:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        por_categoria = dict(zip(df["path_category"].astype(str), df[col]))
        x = [float(por_categoria.get(cat, 0.0)) for cat in y]
        fig.add_trace(
            go.Bar(
                y=y,
                x=x,
                name=col,
                orientation="h",
                marker_color=SEVERIDAD_COLOR.get(col, SEVERIDAD_COLOR["Unknown"]),
                text=[_int(v) if v else None for v in x],
                textposition="inside",
                hovertemplate=f"%{{y}} — {col}: %{{x}}<extra></extra>",
            )
        )
    fig.update_layout(barmode="stack")
    return _config(fig, titulo, x_titulo="Hallazgos")


def fig_grype_severidad(df: pd.DataFrame, summary: dict | None) -> go.Figure:
    """Barras `matches` por severidad; etiqueta con `distinct_cves` + fixable."""
    summary = summary or {}
    titulo = "Severidad de las coincidencias Grype"
    if df.empty or not {"severity_level", "matches", "distinct_cves"}.issubset(df.columns):
        return _fig_vacia(titulo, "analysis/grype_severity.csv")
    df = df.copy()
    orden = {nombre: i for i, nombre in enumerate(SEVERIDAD_ORDER)}
    df["_orden"] = df["severity_level"].astype(str).map(orden).fillna(len(SEVERIDAD_ORDER))
    df = df.sort_values("_orden")
    sev = df["severity_level"].astype(str)
    matches = pd.to_numeric(df["matches"], errors="coerce").fillna(0)
    cves = pd.to_numeric(df["distinct_cves"], errors="coerce").fillna(0)
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            y=sev,
            x=matches,
            orientation="h",
            marker_color=[SEVERIDAD_COLOR.get(s, SEVERIDAD_COLOR["Unknown"]) for s in sev],
            text=[f"{_int(v)} CVE" for v in cves],
            textposition="outside",
            hovertemplate="%{y}: %{x} coincidencias<br>%{text}<extra></extra>",
        )
    )
    fixable = (summary.get("grype") or {}).get("fixable_share")
    if fixable is not None:
        fig.add_annotation(
            text=f"{_pct_local(fixable)} de las coincidencias tiene versión corregida",
            xref="paper",
            yref="paper",
            x=0.98,
            y=0.98,
            showarrow=False,
            font=dict(size=13),
            bgcolor="rgba(248,250,252,0.9)",
        )
    return _config(fig, titulo, x_titulo="Coincidencias (paquete × CVE)")



def fig_grype_top_packages(df: pd.DataFrame, summary: dict | None) -> go.Figure:
    """Top 15 por `repos`; color por `worst`; hover con matches/CVE/fixable."""
    summary = summary or {}
    titulo = "Paquetes con versiones repetidas en repositorios (top 15)"
    necesarias = {
        "package",
        "package_version",
        "matches",
        "distinct_cves",
        "repos",
        "worst",
        "fixable",
    }
    if df.empty or not necesarias.issubset(df.columns):
        return _fig_vacia(titulo, "analysis/grype_top_packages.csv")
    df = df.copy()
    df["repos"] = pd.to_numeric(df["repos"], errors="coerce").fillna(0)
    df = df.sort_values("repos", ascending=False).head(15)
    y = df["package"].astype(str) + "@" + df["package_version"].astype(str)
    worst = df["worst"].astype(str)
    matches = pd.to_numeric(df["matches"], errors="coerce").fillna(0)
    cves = pd.to_numeric(df["distinct_cves"], errors="coerce").fillna(0)
    hover_fixable = [_pct_local(v) for v in df["fixable"]]
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            y=y,
            x=df["repos"],
            orientation="h",
            marker_color=[SEVERIDAD_COLOR.get(w, SEVERIDAD_COLOR["Unknown"]) for w in worst],
            customdata=list(
                zip(
                    [_int(v) for v in matches],
                    [_int(v) for v in cves],
                    hover_fixable,
                    worst,
                )
            ),
            text=[f"{_int(v)} repos" for v in df["repos"]],
            textposition="outside",
            hovertemplate=(
                "<b>%{y}</b><br>"
                "Peor severidad: %{customdata[3]}<br>"
                "Coincidencias: %{customdata[0]}<br>"
                "CVE distintas: %{customdata[1]}<br>"
                "Con corrección: %{customdata[2]}<extra></extra>"
            ),
        )
    )
    total = summary.get("systemic_packages")
    if total is not None:
        fig.add_annotation(
            text=f"{_int(total)} versiones de paquetes se repiten en ≥3 repositorios",
            xref="paper",
            yref="paper",
            x=0.98,
            y=0.98,
            showarrow=False,
            font=dict(size=13),
            bgcolor="rgba(248,250,252,0.9)",
        )
    return _config(fig, titulo, x_titulo="Repositorios en los que aparece la versión")


def fig_riesgo(df: pd.DataFrame, summary: dict | None) -> go.Figure:
    """Top 10 por score_total: score_deps + score_code; texto con risk_top3."""
    summary = summary or {}
    titulo = "Ranking de riesgo por repositorio (top 10)"
    necesarias = {"repository", "short_name", "score_deps", "score_code", "score_total"}
    if df.empty or not necesarias.issubset(df.columns):
        return _fig_vacia(titulo, "analysis/repo_risk_ranking.csv")
    df = df.copy()
    for col in ("score_deps", "score_code", "score_total"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    df = df.sort_values("score_total", ascending=False).head(10)
    y = df["short_name"].astype(str)
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            y=y,
            x=df["score_deps"],
            name="Dependencias (Grype)",
            orientation="h",
            marker_color=COLOR_GRYPE,
            text=[_int(v) for v in df["score_deps"]],
            textposition="auto",
            hovertemplate="%{y}: %{x}<extra>Dependencias (Grype)</extra>",
        )
    )
    fig.add_trace(
        go.Bar(
            y=y,
            x=df["score_code"],
            name="Código (CodeQL)",
            orientation="h",
            marker_color=COLOR_CODEQL,
            text=[_int(v) for v in df["score_code"]],
            textposition="auto",
            hovertemplate="%{y}: %{x}<extra>Código (CodeQL)</extra>",
        )
    )
    fig.update_layout(barmode="stack")
    top3 = summary.get("risk_top3") or []
    if top3:
        fig.add_annotation(
            text="Mayor riesgo: " + ", ".join(str(repo) for repo in top3),
            xref="paper",
            yref="paper",
            x=0.98,
            y=0.98,
            showarrow=False,
            font=dict(size=12),
            bgcolor="rgba(248,250,252,0.9)",
        )
    return _config(fig, titulo, x_titulo="Puntaje de riesgo (score_total)")