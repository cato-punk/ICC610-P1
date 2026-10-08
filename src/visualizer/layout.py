"""Layout de la app Dash (componentes visuales en español).

Este módulo es **puro**: solo construye componentes de Dash a partir de los
datos que recibe; no lee archivos ni tiene estado. La carga de datos vive en
`data.py` y el cableado en `callbacks.py`.

Colores coherentes con los usados en el notebook del Analyzer.
"""

from __future__ import annotations

from dash import dcc, html

# Valor por defecto cuando un dato no está disponible (D7).
NA = "—"

# Pestañas de la interfaz (valor -> etiqueta). El orden es el de presentación.
SECTIONS: dict[str, str] = {
    "resumen": "Resumen",
    "severidad": "Severidad",
    "repositorios": "Repositorios",
    "codeql": "CodeQL",
    "dependencias": "Dependencias",
    "riesgo": "Riesgo",
    "hallazgos": "Hallazgos",
}

# --------------------------------------------------------------------------- #
# Estilos (locales: la demo no carga CSS ni scripts externos)                  #
# --------------------------------------------------------------------------- #
_PAGE = {
    "maxWidth": "1200px",
    "margin": "0 auto",
    "padding": "20px 16px 40px",
    "fontFamily": "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
    "color": "#0f172a",
    "backgroundColor": "#f8fafc",
    "minHeight": "100vh",
}
_H1 = {"fontSize": "24px", "margin": "0 0 4px 0"}
_SUBTITLE = {"color": "#475569", "fontSize": "14px", "marginBottom": "10px"}
_KPIS_ROW = {"display": "flex", "flexWrap": "wrap", "gap": "12px", "margin": "8px 0"}
_CARD = {
    "backgroundColor": "#ffffff",
    "border": "1px solid #e2e8f0",
    "borderRadius": "8px",
    "padding": "12px 16px",
    "minWidth": "150px",
    "flex": "1 1 150px",
}
_CARD_TITULO = {
    "fontSize": "12px",
    "textTransform": "uppercase",
    "letterSpacing": "0.03em",
    "color": "#64748b",
}
_CARD_VALOR = {"fontSize": "26px", "fontWeight": "700", "marginTop": "2px"}
_CARD_DETALLE = {"fontSize": "12px", "color": "#64748b", "marginTop": "2px"}
_REFRESH_ROW = {"display": "flex", "alignItems": "center", "gap": "10px", "margin": "10px 0"}
_BUTTON = {
    "backgroundColor": "#2563eb",
    "color": "#ffffff",
    "border": "none",
    "borderRadius": "6px",
    "padding": "8px 14px",
    "fontSize": "14px",
    "cursor": "pointer",
}
_MUTED = {"color": "#64748b", "fontSize": "13px"}
_WARN_BOX = {
    "backgroundColor": "#fef3c7",
    "border": "1px solid #f59e0b",
    "borderRadius": "8px",
    "padding": "10px 14px",
    "margin": "10px 0",
    "fontSize": "14px",
}
_CARD_BOX = {
    "backgroundColor": "#ffffff",
    "border": "1px solid #e2e8f0",
    "borderRadius": "8px",
    "padding": "16px 18px",
    "marginTop": "16px",
}
_CONTENIDO = {"marginTop": "8px"}
_TABS = {"marginTop": "16px"}
_REPO_CONTROLES = {
    "display": "flex",
    "flexWrap": "wrap",
    "gap": "24px",
    "alignItems": "flex-end",
    "margin": "4px 0 12px",
}
_REPO_LABEL = {
    "fontSize": "12px",
    "textTransform": "uppercase",
    "letterSpacing": "0.03em",
    "color": "#64748b",
    "marginBottom": "4px",
    "display": "block",
}
_REPO_TITULO = {"margin": "20px 0 6px"}
_FOOTER = {
    "borderTop": "1px solid #e2e8f0",
    "marginTop": "28px",
    "paddingTop": "12px",
    "fontSize": "13px",
    "color": "#64748b",
    "lineHeight": "1.5",
}

# Visibilidad del bloque estático de la pestaña «Repositorios» (lo conmuta el
# callback de sección; los gráficos e ids existen siempre en el DOM para que
# Dash valide los callbacks sin `suppress_callback_exceptions`).
REPO_BLOQUE_ESTILO = {"display": "block"}
REPO_BLOQUE_OCULTO = {"display": "none"}


# --------------------------------------------------------------------------- #
# Estructura estática (sin datos)                                              #
# --------------------------------------------------------------------------- #
def build_layout() -> html.Div:
    """Layout base: encabezado, contenedores de datos, pestañas y pie.

    Los contenedores con id (`subtitulo`, `kpis`, `avisos-datos`, `contenido`)
    se rellenan desde `callbacks.py` leyendo `data/processed/` en cada render.
    """
    return html.Div(
        style=_PAGE,
        children=[
            html.Header(
                children=[
                    html.H1("Visualizador de vulnerabilidades — Proyecto P1 (ICC610)", style=_H1),
                    html.Div(id="subtitulo", style=_SUBTITLE),
                ]
            ),
            html.Div(id="kpis", style=_KPIS_ROW),
            html.Div(
                style=_REFRESH_ROW,
                children=[
                    html.Button("Actualizar datos", id="btn-refresh", n_clicks=0, style=_BUTTON),
                    html.Span(
                        "Vuelve a leer data/processed/ sin reiniciar el servidor.",
                        style=_MUTED,
                    ),
                ],
            ),
            html.Div(id="avisos-datos"),
            dcc.Tabs(
                id="secciones",
                value="resumen",
                style=_TABS,
                children=[
                    dcc.Tab(label=etiqueta, value=valor)
                    for valor, etiqueta in SECTIONS.items()
                ],
            ),
            dcc.Loading(
                id="cargando",
                type="default",
                children=html.Div(id="contenido", style=_CONTENIDO),
            ),
            html.Div(
                id="bloque-repos",
                style=REPO_BLOQUE_OCULTO,
                children=[
                    html.Div(
                        style=_REPO_CONTROLES,
                        children=[
                            html.Div(
                                children=[
                                    html.Label("Métrica", htmlFor="select-metrica", style=_REPO_LABEL),
                                    dcc.Dropdown(
                                        id="select-metrica",
                                        options=[
                                            {
                                                "label": "Vulnerabilidades Grype",
                                                "value": "grype_vulnerabilities",
                                            },
                                            {
                                                "label": "Hallazgos CodeQL",
                                                "value": "codeql_findings",
                                            },
                                            {
                                                "label": "Componentes del SBOM (Syft)",
                                                "value": "sbom_components",
                                            },
                                            {
                                                "label": "Puntaje de riesgo total",
                                                "value": "score_total",
                                            },
                                        ],
                                        value="grype_vulnerabilities",
                                        clearable=False,
                                        style={"minWidth": "280px"},
                                    ),
                                ]
                            ),
                            html.Div(
                                children=[
                                    html.Label("Top-N", htmlFor="select-topn", style=_REPO_LABEL),
                                    dcc.RadioItems(
                                        id="select-topn",
                                        options=[
                                            {"label": "10", "value": 10},
                                            {"label": "15", "value": 15},
                                            {"label": "30", "value": 30},
                                            {"label": "Todos", "value": 0},
                                        ],
                                        value=10,
                                        inline=True,
                                    ),
                                ]
                            ),
                        ],
                    ),
                    dcc.Graph(id="grafico-repos", style={"height": "560px"}),
                    html.Div(id="nota-repos", style=_MUTED),
                    html.H4("Relaciones entre métricas", style=_REPO_TITULO),
                    dcc.Graph(id="grafico-relaciones-1", style={"height": "380px"}),
                    dcc.Graph(id="grafico-relaciones-2", style={"height": "380px"}),
                ],
            ),
            html.Footer(
                style=_FOOTER,
                children=[
                    html.P(
                        "Fuente: data/processed/ (Miner + Analyzer). "
                        "La interfaz se regenera automáticamente al recargar; "
                        "no contiene resultados incrustados."
                    ),
                    html.P(
                        "Nota: la equivalencia entre los niveles SARIF de CodeQL "
                        "(error/warning/note) y las severidades de Grype "
                        "(Critical/High/Medium/Low) es convencional, sirve para ordenar "
                        "y no representa escalas equivalentes. Los conteos de Grype son "
                        "coincidencias (paquete × vulnerabilidad), no CVE distintos."
                    ),
                ],
            ),
            dcc.Store(id="refresh"),
        ],
    )


# --------------------------------------------------------------------------- #
# Constructores de contenido (reciben el paquete de data.load_all())           #
# --------------------------------------------------------------------------- #
def build_subtitle(datos: dict) -> str:
    """Subtítulo con la organización derivada (D6) y la cobertura de análisis."""
    summary = datos.get("summary") or {}
    coverage = summary.get("coverage") or {}
    partes: list[str] = []
    org = datos.get("org") or ""
    if org:
        partes.append(f"Organización: {org}")
    if coverage.get("repositories") is not None:
        partes.append(f"{coverage['repositories']} repositorios analizados")
    if coverage.get("codeql_analyzed") is not None:
        partes.append(f"CodeQL: {coverage['codeql_analyzed']}")
    if coverage.get("grype_scanned") is not None:
        partes.append(f"Grype: {coverage['grype_scanned']}")
    if not partes:
        return "Sin datos de cobertura (falta data/processed/analysis/summary.json)."
    return " · ".join(partes)


def _card(titulo: str, valor: object, detalle: str = "") -> html.Div:
    hijos = [
        html.Div(titulo, style=_CARD_TITULO),
        html.Div(NA if valor is None else str(valor), style=_CARD_VALOR),
    ]
    if detalle:
        hijos.append(html.Div(detalle, style=_CARD_DETALLE))
    return html.Div(hijos, style=_CARD)


def _pct(valor: object) -> object:
    """Formato de porcentaje en español; `None`/ausente -> «—»."""
    if isinstance(valor, (int, float)):
        return f"{valor * 100:.0f} %"
    return NA


def build_kpis(datos: dict) -> list[html.Div]:
    """Fila de tarjetas KPI derivadas de summary.json (sin valores hardcodeados)."""
    summary = datos.get("summary") or {}
    coverage = summary.get("coverage") or {}
    conc_codeql = (summary.get("concentration") or {}).get("CodeQL") or {}
    grype = summary.get("grype") or {}
    return [
        _card("Repositorios", coverage.get("repositories"), "escaneados en total"),
        _card("Hallazgos CodeQL", conc_codeql.get("total"), "en el código de los repos"),
        _card("Coincidencias Grype", grype.get("matches"), "en dependencias (paquete × CVE)"),
        _card("CVE distintas", grype.get("distinct_cves"), "en todas las coincidencias"),
        _card("Con corrección", _pct(grype.get("fixable_share")), "versión corregida disponible"),
        _card("Paquetes sistémicos", summary.get("systemic_packages"), "presentes en ≥3 repos"),
    ]


def build_observations(datos: dict) -> html.Div:
    """Contenido de la pestaña «Resumen»: observaciones generadas por el Analyzer."""
    summary = datos.get("summary") or {}
    observaciones = summary.get("observations") or []
    hijos: list = [
        html.H3("Observaciones del análisis"),
        html.P(
            "Generadas por el Analyzer a partir de data/processed/; "
            "se actualizan al recargar la página.",
            style=_MUTED,
        ),
    ]
    if observaciones:
        hijos.append(html.Ul([html.Li(str(obs)) for obs in observaciones]))
    else:
        hijos.append(
            html.P(
                "No hay observaciones disponibles. Falta "
                "data/processed/analysis/summary.json: ejecuta el notebook del Analyzer "
                "(src/analyzer/notebooks/) y pulsa «Actualizar datos».",
                style=_MUTED,
            )
        )
    return html.Div(hijos, style=_CARD_BOX)


def build_placeholder(etiqueta: str) -> html.Div:
    """Contenido de las pestañas aún no implementadas (Tarea 4/5)."""
    return html.Div(
        [html.H3(etiqueta), html.P("Sección en construcción.", style=_MUTED)],
        style=_CARD_BOX,
    )


def build_alerts(missing: list[str]) -> html.Div:
    """Avisos en español cuando faltan archivos de `data/processed/` (D7)."""
    if not missing:
        return html.Div()
    items = [html.Li(f"Falta {nombre}") for nombre in missing]
    pistas: list[str] = []
    if any(nombre.startswith("analysis/") for nombre in missing):
        pistas.append(
            "Regenera los agregados ejecutando el notebook del Analyzer "
            "(src/analyzer/notebooks/)."
        )
    if any("dataset.csv" in nombre for nombre in missing):
        pistas.append("Regenera el dataset con: python -m miner.dataset_builder")
    if any(nombre.startswith("repositories") for nombre in missing):
        pistas.append("Regenera el inventario con: python -m miner.dataset_builder")
    pistas.append("Pulsa «Actualizar datos» o recarga la página después de regenerarlos.")
    return html.Div(
        [
            html.Strong("Aviso de datos: la vista está incompleta."),
            html.Ul(items),
            html.P(" ".join(pistas), style=_MUTED),
        ],
        style=_WARN_BOX,
    )


def build_caption(texto: str) -> html.P:
    """Párrafo de apoyo bajo una figura (texto plano, sin renderizar HTML)."""
    return html.P(texto, style=_MUTED)


def build_seccion(titulo: str, figure, caption: str = "") -> html.Div:
    """Sección de contenido: encabezado, figura Plotly y nota opcional."""
    hijos: list = [html.H3(titulo), dcc.Graph(figure=figure)]
    if caption:
        hijos.append(build_caption(caption))
    return html.Div(hijos, style=_CARD_BOX)
