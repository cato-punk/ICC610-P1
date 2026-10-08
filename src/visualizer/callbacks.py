"""Callbacks de la app Dash.

Todos los callbacks que muestran datos llaman a `data.load_all()` en cada
ejecución (decisión D2: sin caché), de modo que un refresco del navegador o el
botón «Actualizar datos» releen `data/processed/` sin reiniciar el servidor.
"""

from __future__ import annotations

import time

from dash import Dash, Input, Output, State, html, no_update

from . import data, figures as fig, layout as ui


def _contenido_seccion(seccion: str, datos: dict) -> html.Div:
    """Contenido de cada pestaña (las figuras se construyen al renderizar).

    La pestaña «Repositorios» no entra por aquí: usa el bloque estático
    `bloque-repos` del layout (sus gráficos tienen sus propios callbacks).
    """
    if seccion == "resumen":
        return ui.build_observations(datos)
    if seccion == "severidad":
        return ui.build_seccion(
            "Severidad comparada por herramienta",
            fig.fig_severidad_overview(datos["severity_overview"]),
            caption=(
                "Advertencia: la equivalencia entre niveles SARIF (CodeQL) y "
                "severidades de Grype es convencional (D8); las escalas no son "
                "comparables entre sí."
            ),
        )
    if seccion == "codeql":
        return html.Div(
            [
                ui.build_seccion(
                    "Reglas de CodeQL más frecuentes (top 10)",
                    fig.fig_codeql_reglas(datos["codeql_rules"]),
                ),
                ui.build_seccion(
                    "Hallazgos de CodeQL por categoría de ruta",
                    fig.fig_codeql_categorias(datos["codeql_path_categories"]),
                    caption=fig.texto_codeql_source(datos["summary"]),
                ),
            ]
        )
    if seccion == "dependencias":
        return html.Div(
            [
                ui.build_seccion(
                    "Severidad de las coincidencias Grype",
                    fig.fig_grype_severidad(datos["grype_severity"], datos["summary"]),
                    caption=(
                        "Coincidencias = pares paquete×CVE detectados en el SBOM; "
                        "las CVE distintas son un conteo menor. Son medidas "
                        "distintas, no equivalentes (D8)."
                    ),
                ),
                ui.build_seccion(
                    "Paquetes con versiones repetidas en repositorios (top 15)",
                    fig.fig_grype_top_packages(datos["grype_top_packages"], datos["summary"]),
                ),
            ]
        )
    if seccion == "riesgo":
        return ui.build_seccion(
            "Ranking de riesgo por repositorio (top 10)",
            fig.fig_riesgo(datos["repo_risk_ranking"], datos["summary"]),
        )
    if seccion == "hallazgos":
        return ui.build_placeholder("Hallazgos")  # se implementa en la Tarea 5
    return ui.build_placeholder(ui.SECTIONS.get(seccion, "Resumen"))


def register(app: Dash) -> None:
    """Registra todos los callbacks de la aplicación (los llama `main.build_app`)."""

    @app.callback(
        Output("subtitulo", "children"),
        Output("kpis", "children"),
        Input("refresh", "data"),
    )
    def _actualizar_encabezado(_refresh) -> tuple[str, list]:
        datos = data.load_all()
        return ui.build_subtitle(datos), ui.build_kpis(datos)

    @app.callback(Output("avisos-datos", "children"), Input("refresh", "data"))
    def _actualizar_avisos(_refresh):
        # D7: si falta algún archivo, se muestra un aviso en español; si no, vacío.
        return ui.build_alerts(list(data.load_all()["missing"]))

    @app.callback(
        Output("contenido", "children"),
        Output("bloque-repos", "style"),
        Input("secciones", "value"),
        Input("refresh", "data"),
    )
    def _actualizar_seccion(seccion, _refresh):
        datos = data.load_all()
        if seccion == "repositorios":
            return None, ui.REPO_BLOQUE_ESTILO
        return _contenido_seccion(seccion, datos), ui.REPO_BLOQUE_OCULTO

    @app.callback(
        Output("grafico-repos", "figure"),
        Output("nota-repos", "children"),
        Input("select-metrica", "value"),
        Input("select-topn", "value"),
        Input("refresh", "data"),
    )
    def _actualizar_grafico_repos(metrica, top_n, _refresh):
        datos = data.load_all()
        figura = fig.fig_repositorios(
            datos["repositories"],
            datos["repo_risk_ranking"],
            datos["summary"],
            metrica=metrica,
            top_n=top_n,
        )
        nota = fig.texto_concentracion(datos["summary"], metrica)
        return figura, (ui.build_caption(nota) if nota else None)

    @app.callback(Output("grafico-relaciones-1", "figure"), Input("refresh", "data"))
    def _actualizar_relaciones_1(_refresh):
        datos = data.load_all()
        return fig.fig_relaciones(datos["repositories"], datos["summary"], pareja="components")

    @app.callback(Output("grafico-relaciones-2", "figure"), Input("refresh", "data"))
    def _actualizar_relaciones_2(_refresh):
        datos = data.load_all()
        return fig.fig_relaciones(datos["repositories"], datos["summary"], pareja="codeql")

    @app.callback(
        Output("refresh", "data"),
        Input("btn-refresh", "n_clicks"),
        State("refresh", "data"),
    )
    def _boton_actualizar(n_clicks, _actual):
        if not n_clicks:
            return no_update  # carga inicial: no hay nada que refrescar aún
        return time.time()