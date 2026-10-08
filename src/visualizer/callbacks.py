"""Callbacks de la app Dash."""

from __future__ import annotations

import time

from dash import Dash, Input, Output, State, html, no_update

from . import data, figures as fig, layout as ui


def _contenido_seccion(seccion: str, datos: dict) -> html.Div:
    """Contenido de cada pestaña (las figuras se construyen al renderizar)."""
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
        return ui.build_alerts(list(data.load_all()["missing"]))

    @app.callback(
        Output("contenido", "children"),
        Output("bloque-repos", "style"),
        Output("bloque-hallazgos", "style"),
        Input("secciones", "value"),
        Input("refresh", "data"),
    )
    def _actualizar_seccion(seccion, _refresh):
        datos = data.load_all()
        if seccion == "repositorios":
            return None, ui.REPO_BLOQUE_ESTILO, ui.HALLAZGOS_BLOQUE_OCULTO
        if seccion == "hallazgos":
            return None, ui.REPO_BLOQUE_OCULTO, ui.HALLAZGOS_BLOQUE_ESTILO
        return (
            _contenido_seccion(seccion, datos),
            ui.REPO_BLOQUE_OCULTO,
            ui.HALLAZGOS_BLOQUE_OCULTO,
        )

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
        Output("filtro-repositorio", "options"),
        Output("filtro-severidad", "options"),
        Input("refresh", "data"),
    )
    def _poblar_filtros_hallazgos(_refresh):
        """Rellena los dropdowns con los valores presentes en dataset.csv."""
        hallazgos = data.load_all()["findings"]
        repos: list[dict] = []
        severidades: list[dict] = []
        if not hallazgos.empty:
            repos = [
                {"label": str(repo), "value": str(repo)}
                for repo in sorted(hallazgos["repository"].dropna().unique(), key=str)
            ]
            valores_sev = list(hallazgos["severity_level"].dropna().unique())
            orden = {nombre: i for i, nombre in enumerate(data.GRYPE_SEVERITY_ORDER)}
            severidades = [
                {"label": str(sev), "value": str(sev)}
                for sev in sorted(
                    valores_sev, key=lambda s: orden.get(str(s), len(orden))
                )
            ]
        return repos, severidades

    @app.callback(
        Output("tabla-hallazgos", "data"),
        Output("conteo-hallazgos", "children"),
        Output("tabla-hallazgos", "page_current"),
        Input("filtro-fuente", "value"),
        Input("filtro-repositorio", "value"),
        Input("filtro-severidad", "value"),
        Input("busqueda-hallazgos", "value"),
        Input("refresh", "data"),
    )
    def _actualizar_tabla_hallazgos(fuente, repositorio, severidad, busqueda, _refresh):
        """Filtros combinados con AND + búsqueda insensible a mayúsculas."""
        hallazgos = data.load_all()["findings"]
        if hallazgos.empty:
            return [], "Sin hallazgos para los filtros seleccionados.", 0
        df = hallazgos.copy()
        if fuente and fuente != "ambos":
            df = df[df["source"] == fuente]
        if repositorio:
            df = df[df["repository"] == repositorio]
        if severidad:
            df = df[df["severity_level"] == severidad]
        termino = str(busqueda or "").strip()
        if termino:
            cadenas = df[["vulnerability_id", "title", "package", "location"]].fillna("")
            mascara = (
                cadenas["vulnerability_id"].astype(str).str.contains(termino, case=False, na=False)
                | cadenas["title"].astype(str).str.contains(termino, case=False, na=False)
                | cadenas["package"].astype(str).str.contains(termino, case=False, na=False)
                | cadenas["location"].astype(str).str.contains(termino, case=False, na=False)
            )
            df = df[mascara]
        df = df.reset_index(drop=True)
        # Dash no serializa NaN: se reemplaza por None antes de to_dict.
        if "start_line" in df.columns:
            df["start_line"] = df["start_line"].where(df["start_line"].notna(), None)
        registros = df.to_dict("records")
        total = len(registros)
        if total == 0:
            return [], "Sin hallazgos para los filtros seleccionados.", 0
        conteo = "1 hallazgo" if total == 1 else f"{total} hallazgos"
        return registros, conteo, 0

    @app.callback(
        Output("refresh", "data"),
        Input("btn-refresh", "n_clicks"),
        State("refresh", "data"),
    )
    def _boton_actualizar(n_clicks, _actual):
        if not n_clicks:
            return no_update  # carga inicial: no hay nada que refrescar aún
        return time.time()