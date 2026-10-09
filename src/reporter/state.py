"""Estado de rotación de aspectos entre ejecuciones programadas.

Replica el mecanismo de cache-memory del workflow de referencia
``daily-action-setup-security-audit``: en cada corrida se reexaminan aspectos
previos (60%) y se incorporan aspectos nuevos (40%), evitando cubrir siempre lo
mismo. El estado se guarda en un JSON simple que el workflow persiste con
``actions/cache``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_STATE_FILE = Path(".reporter_state.json")


def default_state() -> dict:
    return {
        "last_run": None,
        "completed_aspects": [],
        "aspect_rotation_index": 0,
        "known_findings": [],
    }


def load_state(path: Path = DEFAULT_STATE_FILE) -> dict:
    """Carga el estado, devolviendo uno nuevo si no existe o está corrupto."""
    path = Path(path)
    if not path.is_file():
        return default_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default_state()
    if not isinstance(data, dict):
        return default_state()
    state = default_state()
    state.update(data)
    return state


def save_state(state: dict, path: Path = DEFAULT_STATE_FILE) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def select_aspects(state: dict, aspects: list[str], count: int = 4) -> tuple[list[str], dict]:
    """Selecciona ``count`` aspectos con la estrategia 60/40.

    Devuelve ``(seleccionados, estado_actualizado)``. Reutiliza primero los
    aspectos ya cubiertos (60%) y añade aspectos nuevos (40%); si estos se
    agotan, reinicia el ciclo.
    """
    aspects = list(aspects)
    completed = [a for a in state.get("completed_aspects", []) if a in aspects]
    pending = [a for a in aspects if a not in completed]

    reuse_n = (count * 3) // 5
    new_n = count - reuse_n

    selected: list[str] = []
    for aspect in completed[:reuse_n]:
        if aspect not in selected:
            selected.append(aspect)
    for aspect in pending[:new_n]:
        if aspect not in selected:
            selected.append(aspect)

    # Rellenar hasta ``count`` si hubo pocos aspectos previos/nuevos.
    for aspect in completed[reuse_n:] + pending[new_n:]:
        if len(selected) >= count:
            break
        if aspect not in selected:
            selected.append(aspect)

    if not selected:
        selected = aspects[:count]

    state = dict(state)
    state["completed_aspects"] = list(dict.fromkeys(completed + selected))
    if pending and not set(pending) - set(selected):
        # Se cubrieron todos los aspectos: preparar un nuevo ciclo.
        state["completed_aspects"] = []
        state["aspect_rotation_index"] = int(state.get("aspect_rotation_index", 0)) + 1
    state["last_run"] = datetime.now(timezone.utc).isoformat()

    ordered = [a for a in aspects if a in selected]
    return ordered, state
