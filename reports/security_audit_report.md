# Auditoría de seguridad del repositorio

> Generado por el Reporter (inspector `0.1.0`) el 2026-10-09T13:15:16.495891+00:00.
> Raíz analizada: `/home/runner/work/ICC610-P1/ICC610-P1` · Archivos inspeccionados: 52 · Aspectos: secret-handling, command-injection, network-requests, supply-chain.
> ⚠️ **Reporte determinista (fallback):** el LLM no se utilizó (Define LLM_API_KEY en el entorno (ver .env.example).). El contenido no depende del modelo.

## Resumen ejecutivo

Se identificaron 1 hallazgos respaldados por evidencia (medium: 1). Cada uno referencia archivo y línea; los detalles y las recomendaciones aparecen a continuación.

## Alcance y método

El inspector recorre el repositorio de forma determinista y aplica reglas basadas en patrones observables sobre código, dependencias, configuración y workflows. Cada afirmación se respalda con la evidencia listada (archivo, línea y fragmento). No se ejecuta código del repositorio.

## Hallazgos

| Severidad | Aspecto | Hallazgo | Evidencia |
|---|---|---|---|
| 🟡 Media | `supply-chain` | Imagen base sin fijar por digest | `.devcontainer/Dockerfile:1` |

### Detalle

#### 🟡 Media — Imagen base sin fijar por digest

- **Aspecto:** `supply-chain`
- **ID:** `supply-chain:sc-docker-unpinned`
- **Confianza:** high

Una etiqueta de imagen puede reescribirse y alterar la build.

**Evidencia:**

- `.devcontainer/Dockerfile:1` — regla `sc-docker-unpinned`

<details><summary>Fragmento</summary>

```
FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm
```

</details>

**Recomendación:** Fijar la imagen base por digest (@sha256:...).

## Limitaciones

El análisis es heurístico y se basa en lo que es observable en los archivos del repositorio; no sustituye una revisión manual ni un escáner dedicado. Los hallazgos son indicios respaldados por evidencia, no confirmaciones de explotabilidad.

## Apéndice: evidencia

| ID | Aspecto | Archivo:línea | Fragmento |
|---|---|---|---|
| `3913f027c3b6` | `supply-chain` | `.devcontainer/Dockerfile:1` | `FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm` |
