# Proyecto P1 - Ciberseguridad (ICC610)

Herramienta para detectar, analizar y visualizar vulnerabilidades en los repositorios
públicos de una organización de GitHub, y para auditar la seguridad de este mismo
repositorio con apoyo de un modelo de lenguaje.

## Componentes

| Componente | Carpeta | Función |
|---|---|---|
| **Miner** | `src/miner/` | Clona repos, ejecuta CodeQL, Syft y Grype, y construye el dataset |
| **Analyzer** | `src/analyzer/` | Notebooks que analizan el dataset |
| **Visualizer** | `src/visualizer/` | Interfaz para explorar los resultados |
| **Reporter** | `src/reporter/` | Audita este repositorio con un LLM y genera un reporte en Markdown |

Flujo principal: `Miner → Analyzer → Visualizer`. El Reporter es independiente: no usa
datos del Miner ni del Analyzer, solo analiza este repositorio.

## Estructura

```
.
├── .devcontainer/    # Dev Container (Python, Node, CodeQL, Syft, Grype)
├── .github/          # Workflows
├── data/
│   ├── raw/          # Clones, SARIF, SBOM y reportes de Grype (no se versiona)
│   └── processed/    # Dataset unificado (CSV/JSON)
├── docs/             # Documentación detallada y decisiones de diseño
├── reports/          # Salida del Reporter
├── src/
│   ├── miner/        # CLI, clonado, runners de CodeQL/Syft/Grype, dataset_builder
│   ├── analyzer/     # notebooks/ y utils/
│   ├── visualizer/   # app/
│   └── reporter/     # inspector, cliente LLM y generador de Markdown
├── tests/
├── .env.example
└── pyproject.toml
```

## Instalación

### Opción recomendada: Dev Container

Requiere Docker y VS Code con la extensión *Dev Containers*.

1. Clona el repositorio y ábrelo en VS Code.
2. Define tus credenciales **en tu máquina**, antes de abrir VS Code
   (por ejemplo en `~/.bashrc`):
```bash
   export GITHUB_TOKEN=...      # opcional, eleva el límite de la API de GitHub
   export LLM_API_KEY=...       # necesario para el Reporter
```
3. `Ctrl+Shift+P` → **Dev Containers: Reopen in Container**.

El contenedor incluye Python, Node, CodeQL, Syft y Grype con versiones fijas.

### Sin Dev Container

Necesitas Python 3.10+, Git, CodeQL CLI, Syft y Grype en el `PATH`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Configuración

Los secretos nunca se guardan en el repositorio. Copia `.env.example` a `.env`
(ignorado por Git) o usa variables de entorno:

```
GITHUB_TOKEN=
LLM_API_KEY=
```

## Uso

### Miner

```bash
# Escanear una organización (CodeQL + SBOM)
miner scan --organization <org> --limit 30 --sort-by stars

# Escanear un solo repositorio
miner scan --repo OWASP/NodeGoat

# Solo SBOM, reutilizando clones existentes
miner sbom --organization <org>

# Vulnerabilidades de dependencias con Grype
miner grype --organization <org>

# Dataset unificado en data/processed/
python -m miner.dataset_builder --grype data/raw/grype/grype-report.json
```

Todas las opciones están en [`docs/README.es.md`](docs/README.es.md).


### Analyzer

```bash
python -m miner.dataset_builder
jupyter nbconvert --to notebook --execute --inplace \
  src/analyzer/notebooks/01_analisis_pallets_eco.ipynb
```

Las tablas resultantes quedan en `data/processed/analysis/`.


### Reporter

```bash
python -m reporter.cli     # genera reports/security_audit_report.md
```

*(En desarrollo.)*

## Pruebas

```bash
pytest
```

## Documentación

- [`docs/README.es.md`](docs/README.es.md) - Miner en español
- [`docs/README.md`](docs/README.md) - Miner in English
- [`docs/design-decisions.md`](docs/design-decisions.md) - Decisiones de diseño
