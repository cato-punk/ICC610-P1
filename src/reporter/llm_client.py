"""Cliente del modelo de lenguaje. La clave se lee SOLO desde variables de entorno."""

import os


def get_api_key() -> str:
    key = os.environ.get("LLM_API_KEY")
    if not key:
        raise RuntimeError("Define LLM_API_KEY en el entorno (ver .env.example).")
    return key


def analyze(evidence: dict) -> str:
    """Envía la evidencia al LLM y devuelve su interpretación."""
    raise NotImplementedError
