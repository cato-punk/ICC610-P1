"""Pruebas de la rotación de aspectos (estrategia 60/40)."""

from __future__ import annotations

from reporter.repo_inspector import ASPECTS
from reporter.state import default_state, load_state, save_state, select_aspects


def test_default_state_shape():
    state = default_state()
    assert state["completed_aspects"] == []
    assert state["aspect_rotation_index"] == 0


def test_load_missing_returns_default(tmp_path):
    assert load_state(tmp_path / "nope.json") == default_state()


def test_load_corrupt_returns_default(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{no es json", encoding="utf-8")
    assert load_state(path) == default_state()


def test_load_non_dict_returns_default(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert load_state(path) == default_state()


def test_select_aspects_empty_catalog():
    selected, state = select_aspects(default_state(), [], count=4)
    assert selected == []
    assert state["completed_aspects"] == []


def test_save_load_roundtrip(tmp_path):
    path = tmp_path / "state.json"
    save_state({"last_run": "x", "completed_aspects": ["secret-handling"]}, path)
    loaded = load_state(path)
    assert loaded["last_run"] == "x"
    assert loaded["completed_aspects"] == ["secret-handling"]


def test_select_aspects_count_and_membership():
    selected, state = select_aspects(default_state(), ASPECTS, count=4)
    assert len(selected) == 4
    assert set(selected) <= set(ASPECTS)
    assert state["completed_aspects"]
    assert state["last_run"] is not None


def test_select_aspects_rotates_and_cycles():
    state = default_state()
    seen: set[str] = set()
    for _ in range(10):
        selected, state = select_aspects(state, ASPECTS, count=4)
        assert selected
        seen.update(selected)
    assert seen == set(ASPECTS)
