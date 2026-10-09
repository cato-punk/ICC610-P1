"""Cliente del modelo de lenguaje (API compatible con OpenAI).

La clave se lee **solo** desde variables de entorno (o desde un ``.env`` no
versionado). El modelo nunca introduce hallazgos: recibe la evidencia
determinista y devuelve un resumen más recomendaciones para ``finding_id`` que
ya existen. Cualquier respuesta que cite un hallazgo inexistente se descarta.

Si el LLM no está configurado o falla, ``analyze`` devuelve un
:class:`LLMAnalysis` con ``used_fallback=True`` para que el reporte pueda
generarse igualmente en modo determinista.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

import requests

from .models import InspectionResult, LLMAnalysis

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT = 60.0
DEFAULT_MAX_RETRIES = 2

SYSTEM_PROMPT = (
    "Eres un auditor de seguridad de software. Recibes evidencia objetiva "
    "(archivo, línea y fragmento) recolectada de un repositorio. Tu tarea es "
    "resumir los hallazgos y proponer recomendaciones concretas. Reglas "
    "estrictas: (1) no inventes problemas ni archivos que no aparezcan en la "
    "evidencia; (2) cita siempre el finding_id proporcionado; (3) si la "
    "evidencia es insuficiente, dilo explícitamente; (4) responde únicamente "
    "con el JSON solicitado."
)


def _find_dotenv() -> Optional[Path]:
    """Localiza el ``.env`` del proyecto, o ``None`` si no existe."""
    seen: set[Path] = set()
    for start in (Path(__file__).resolve().parent, Path.cwd().resolve()):
        for directory in (start, *start.parents):
            if directory in seen:
                continue
            seen.add(directory)
            candidate = directory / ".env"
            if candidate.is_file():
                return candidate
    return None


def _parse_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def _load_dotenv() -> None:
    env_file = _find_dotenv()
    if env_file is None:
        return
    for key, value in _parse_dotenv(env_file).items():
        os.environ.setdefault(key, value)


_load_dotenv()


def get_api_key() -> str:
    key = os.environ.get("LLM_API_KEY")
    if not key:
        raise RuntimeError("Define LLM_API_KEY en el entorno (ver .env.example).")
    return key


def get_base_url() -> str:
    return os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def get_model() -> str:
    return os.environ.get("LLM_MODEL", DEFAULT_MODEL)


def get_timeout() -> float:
    try:
        return float(os.environ.get("LLM_TIMEOUT", DEFAULT_TIMEOUT))
    except ValueError:
        return DEFAULT_TIMEOUT


def _build_prompt(result: InspectionResult) -> str:
    """Construye el mensaje de usuario con evidencia y formato de salida."""
    by_id = {e.evidence_id: e for e in result.evidence}
    findings_payload = []
    for finding in result.findings:
        locations = [
            {
                "file": by_id[eid].file,
                "start_line": by_id[eid].start_line,
                "snippet": by_id[eid].snippet,
            }
            for eid in finding.evidence_ids
            if eid in by_id
        ]
        findings_payload.append(
            {
                "finding_id": finding.finding_id,
                "aspect": finding.aspect,
                "severity": finding.severity.value,
                "title": finding.title,
                "description": finding.description,
                "locations": locations,
            }
        )

    valid_ids = sorted(f.finding_id for f in result.findings)
    return (
        "Evidencia recolectada del repositorio (JSON):\n"
        f"{json.dumps(findings_payload, ensure_ascii=False, indent=2)}\n\n"
        "Responde SOLO con un objeto JSON con esta forma exacta:\n"
        '{"summary": "<resumen ejecutivo en 1-3 párrafos>", '
        '"findings": [{"finding_id": "<id>", "note": "<explicación breve>", '
        '"remediation": "<acción concreta>"}]}\n'
        f"IDs de hallazgo válidos: {', '.join(valid_ids) if valid_ids else '(ninguno)'}.\n"
        "No incluyas finding_id fuera de esa lista."
    )


def _loads_json(content: str) -> dict:
    """Parsea JSON tolerando vallas de Markdown ```json ... ```."""
    text = content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    text = text.strip()
    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("La respuesta del LLM no contiene un objeto JSON.")
        text = text[start : end + 1]
    return json.loads(text)


def _post_with_retries(
    url: str,
    headers: dict[str, str],
    payload: dict,
    timeout: float,
    max_retries: int,
):
    last_exc: Exception = RuntimeError("sin intentos")
    for attempt in range(max_retries + 1):
        try:
            response = requests.post(
                url, headers=headers, json=payload, timeout=timeout
            )
            response.raise_for_status()
            return response
        except Exception as exc:  # noqa: BLE001 - se propaga tras agotar
            last_exc = exc
            if attempt < max_retries:
                time.sleep(0.5 * (attempt + 1))
    raise last_exc


def _analyze_with_llm(
    result: InspectionResult,
    api_key: str,
    base_url: str,
    model: str,
    timeout: float,
    max_retries: int,
) -> LLMAnalysis:
    url = f"{base_url}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_prompt(result)},
        ],
    }

    response = _post_with_retries(url, headers, payload, timeout, max_retries)
    data = response.json()
    content = data["choices"][0]["message"]["content"]
    parsed = _loads_json(content)

    valid_ids = {f.finding_id for f in result.findings}
    recommendations: dict[str, str] = {}
    for item in parsed.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        finding_id = item.get("finding_id")
        if finding_id not in valid_ids:
            continue
        text = item.get("remediation") or item.get("note") or ""
        text = str(text).strip()
        if text:
            recommendations[finding_id] = text

    return LLMAnalysis(
        summary=str(parsed.get("summary", "")).strip(),
        recommendations=recommendations,
        used_fallback=False,
        model=model,
    )


def analyze(
    result: InspectionResult,
    *,
    use_llm: bool = True,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    timeout: Optional[float] = None,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> LLMAnalysis:
    """Interpreta la evidencia con el LLM, o cae al modo determinista.

    Nunca lanza: ante cualquier fallo (clave ausente, error HTTP, timeout o
    JSON inválido) devuelve ``LLMAnalysis(used_fallback=True, error=...)``.
    """
    if not use_llm:
        return LLMAnalysis(used_fallback=True, error="LLM deshabilitado (--no-llm).")

    try:
        key = api_key or get_api_key()
        return _analyze_with_llm(
            result,
            api_key=key,
            base_url=base_url or get_base_url(),
            model=model or get_model(),
            timeout=timeout if timeout is not None else get_timeout(),
            max_retries=max_retries,
        )
    except Exception as exc:  # noqa: BLE001 - el fallback es el contrato público
        return LLMAnalysis(used_fallback=True, error=str(exc))
