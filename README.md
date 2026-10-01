# Proyecto P1 - Ciberseguridad (ICC610)

Miner de vulnerabilidades para organizaciones de GitHub. Usa CodeQL para el
analisis de seguridad y Syft para la generacion de SBOM (CycloneDX).

## Estructura

```
.
├── analyzer/          # CodeQL (codeql.py) y parseo de SARIF (sarif.py)
├── data/              # Datos de entrada/salida generados
├── docs/              # Documentacion (README completo en espanol e ingles)
├── miner/             # Orquestacion: CLI, API de GitHub y operaciones git
├── reporter/          # Modelos de datos y generacion de SBOM
├── tests/             # Pruebas unitarias
└── visualizer/        # Visualizacion de resultados
```

## Documentacion

La documentacion completa, con instalacion, uso y formato de salida, esta en:

- [`docs/README.es.md`](docs/README.es.md) - Espanol
- [`docs/README.md`](docs/README.md) - English

## Instalacion

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
```

## Requisitos externos

Ademas de las dependencias de Python, la herramienta orquesta dos binarios
externos que deben estar en el `PATH`:

- [CodeQL CLI](https://codeql.github.com/docs/codeql-cli/)
- [Syft](https://github.com/anchore/syft) (opcional, solo para SBOM)

## Configuracion

Crear un archivo `.env` en la raiz del proyecto (no se versiona):

```
GITHUB_TOKEN=ghp_your_token_here
```

Ver `.env.example`.

## Uso

```powershell
# Escanear una organizacion completa (CodeQL + SBOM)
miner scan --organization <org> -O results.json

# Escanear un solo repositorio
miner scan --repo OWASP/NodeGoat -O nodegoat.json

# Solo SBOM, reutilizando clones existentes
miner sbom --organization <org> --workdir repos --output-dir sbom-output
```

## Pruebas

```powershell
pytest
```

## Nota sobre datos generados

Los resultados de escaneo (`results.json`, `nodegoat.json`, SBOMs y logs) son
salidas generadas y estan excluidas del control de versiones. Para generarlas,
ver la seccion de uso en `docs/`.