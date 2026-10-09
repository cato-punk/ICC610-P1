"""Punto de entrada del Visualizer: `visualizer` o `python -m visualizer.main`."""

from __future__ import annotations

from dash import Dash

from . import callbacks
from .layout import build_layout


def build_app() -> Dash:
    """Crea la app Dash con su layout y sus callbacks registrados."""
    app = Dash(__name__, title="Visualizador de vulnerabilidades — ICC610")
    app.layout = build_layout()
    callbacks.register(app)
    return app


def main() -> None:
    """Arranca el servidor en 127.0.0.1:8050"""
    build_app().run(host="127.0.0.1", port=8050, debug=False)


if __name__ == "__main__":
    main()
