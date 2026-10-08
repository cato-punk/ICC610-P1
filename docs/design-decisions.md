# Decisiones de diseño

| Decisión | Motivo |
|---|---|
| Layout `src/` con un paquete por componente | Mantiene Miner, Analyzer, Visualizer y Reporter separados, como pide la especificación |
| Reporter independiente del flujo Miner → Analyzer → Visualizer | Audita el propio repositorio; no consume datos del Miner |
| `data/raw/` (no versionado) y `data/processed/` (versionado) | Los clones y SARIF son pesados y regenerables; el dataset final es un resultado entregable |
| Dataset en CSV y JSON con columnas comunes para CodeQL y Grype | Los notebooks y el Visualizer lo leen sin transformaciones manuales |
| Dev Container con versiones fijas de CodeQL, Syft y Grype | Reproducibilidad: el mismo entorno para cualquiera que clone el repo |
| Secretos solo por variables de entorno (`.env.example` como plantilla) | Ninguna credencial se almacena en el repositorio |
| `miner scan`, `sbom` y `grype` comparten `data/raw/sbom-output/sboms` | Cada comando puede reutilizar la salida de los anteriores sin flags extra |
| Stack del **Visualizer**: **Dash 3 + Plotly, Python** | Elegido por el usuario: single-page app en Python, sin servidor JS propio y reproducible en el Dev Container existente |
| Modelo de lenguaje del **Reporter**: **pendiente** | No forma parte de este plan; el Reporter no consume datos del Miner ni del Analyzer |
| Comunicación Miner/Analyzer/Visualizer **por archivos** en `data/processed/` | Separación de componentes: no hay imports entre `miner`, `analyzer` y `visualizer`; cada uno se puede ejecutar y probar por separado |
| Carga de datos en **tiempo de ejecución** (sin caché) | «Actualizar datos» o recargar el navegador refleja datasets nuevos sin reconstrucción manual |



