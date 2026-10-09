# Visualizer (Dash 3 + Plotly, Python)

Interfaz de exploración de los resultados del proyecto P1 (ICC610). Es una
aplicación **single-page** en Python con Dash 3 y Plotly; no requiere servidor JS
propio ni dependencias fuera de las ya instaladas en el Dev Container.

## Arranque

```bash
visualizer            # o: python -m visualizer.main
# → http://127.0.0.1:8050/
```

Escucha en `127.0.0.1:8050` con `debug=False` (sin debugger/PIN de Dash).

## Estructura de módulos

| Módulo | Rol |
|---|---|
| `data.py` | Lectura y normalización de `data/processed/` (`load_all()`, sin caché; lista `missing` para avisos) |
| `figures.py` | Constructores puros de figuras Plotly (`fig_*`) desde los CSV de `analysis/` y `summary.json` |
| `layout.py` | Layout estático: encabezado, KPIs, pestañas y bloques de Repositorios y Hallazgos |
| `callbacks.py` | Callbacks Dash: secciones, gráficos, filtros y botón «Actualizar datos» |
| `main.py` | `build_app()` y arranque del servidor |

## Datos que consume (solo lectura)

- `data/processed/repositories.csv` — inventario de repositorios (KPIs, Repositorios, Relaciones).
- `data/processed/dataset.csv` — una fila por hallazgo (tabla «Hallazgos»; actualmente 386 filas: 62 de CodeQL y 324 de Grype).
- `data/processed/analysis/*.csv` — agregados del Analyzer (severidad, reglas, categorías de ruta, Grype y riesgo).
- `data/processed/analysis/summary.json` — KPIs, concentración, correlaciones y observaciones.

Secciones disponibles: **Resumen** (observaciones), **Severidad**, **Repositorios**
(métrica + Top-N + relaciones entre métricas), **CodeQL**, **Dependencias**,
**Riesgo** y **Hallazgos** (tabla paginada con filtros combinables).

## Regeneración de datos

Re-ejecuta el Miner y el notebook del Analyzer y recarga el navegador (o pulsa
«Actualizar datos»): el Visualizer no guarda copias y relee el disco en cada
render. No necesita `GITHUB_TOKEN` ni `LLM_API_KEY`.
