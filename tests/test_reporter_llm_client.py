"""Pruebas del cliente LLM y del mecanismo de fallback."""

from __future__ import annotations

import json

import pytest

from reporter import llm_client
from reporter.repo_inspector import collect_evidence


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _payload(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


def test_no_llm_returns_fallback(sample_repo):
    result = collect_evidence(sample_repo)
    analysis = llm_client.analyze(result, use_llm=False)
    assert analysis.used_fallback is True
    assert analysis.summary == ""


def test_missing_key_falls_back(sample_repo, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    result = collect_evidence(sample_repo)
    analysis = llm_client.analyze(result, max_retries=0)
    assert analysis.used_fallback is True
    assert "LLM_API_KEY" in (analysis.error or "")


def test_success_filters_unknown_finding_ids(sample_repo, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    result = collect_evidence(sample_repo)
    valid_id = result.findings[0].finding_id
    content = json.dumps(
        {
            "summary": "resumen",
            "findings": [
                {"finding_id": valid_id, "note": "nota", "remediation": "arreglar"},
                {"finding_id": "fantasma:x", "remediation": "ignorar"},
            ],
        }
    )
    monkeypatch.setattr(
        llm_client.requests, "post", lambda *a, **k: FakeResponse(_payload(content))
    )

    analysis = llm_client.analyze(result, max_retries=0)

    assert analysis.used_fallback is False
    assert analysis.summary == "resumen"
    assert analysis.recommendations == {valid_id: "arreglar"}


def test_http_error_falls_back(sample_repo, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    result = collect_evidence(sample_repo)

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(llm_client.requests, "post", boom)
    analysis = llm_client.analyze(result, max_retries=0)
    assert analysis.used_fallback is True
    assert "boom" in (analysis.error or "")


def test_invalid_json_falls_back(sample_repo, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    result = collect_evidence(sample_repo)
    monkeypatch.setattr(
        llm_client.requests, "post", lambda *a, **k: FakeResponse(_payload("no json"))
    )
    analysis = llm_client.analyze(result, max_retries=0)
    assert analysis.used_fallback is True


def test_loads_json_strips_markdown_fences():
    assert llm_client._loads_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert llm_client._loads_json('{"b": 2}') == {"b": 2}


def test_success_ignores_non_dict_items(sample_repo, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    result = collect_evidence(sample_repo)
    valid_id = result.findings[0].finding_id
    content = json.dumps(
        {"summary": "s", "findings": ["nope", {"finding_id": valid_id, "note": "ok"}]}
    )
    monkeypatch.setattr(
        llm_client.requests, "post", lambda *a, **k: FakeResponse(_payload(content))
    )
    analysis = llm_client.analyze(result, max_retries=0)
    assert analysis.used_fallback is False
    assert analysis.recommendations == {valid_id: "ok"}


def test_analyze_retries_then_falls_back(sample_repo, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setattr(llm_client.time, "sleep", lambda *_: None)
    calls = {"n": 0}

    def boom(*args, **kwargs):
        calls["n"] += 1
        raise RuntimeError("boom")

    monkeypatch.setattr(llm_client.requests, "post", boom)
    result = collect_evidence(sample_repo)
    analysis = llm_client.analyze(result, max_retries=1)
    assert analysis.used_fallback is True
    assert calls["n"] == 2


def test_loads_json_with_embedded_object():
    assert llm_client._loads_json('bla bla {"a": 3} fin') == {"a": 3}


def test_get_timeout_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("LLM_TIMEOUT", "not-a-number")
    assert llm_client.get_timeout() == llm_client.DEFAULT_TIMEOUT


def test_parse_dotenv_and_load(sample_repo, tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comentario\n\nLLM_API_KEY=from-dotenv\nOTHER=1\n", encoding="utf-8"
    )
    assert llm_client._parse_dotenv(env_file) == {
        "LLM_API_KEY": "from-dotenv",
        "OTHER": "1",
    }
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "_find_dotenv", lambda: env_file)
    llm_client._load_dotenv()
    assert llm_client.get_api_key() == "from-dotenv"


def test_find_dotenv_locates_file(tmp_path, monkeypatch):
    from pathlib import Path

    env_file = tmp_path / ".env"
    env_file.write_text("X=1", encoding="utf-8")
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))
    assert llm_client._find_dotenv() == env_file


def test_get_api_key_missing(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        llm_client.get_api_key()


def test_base_url_and_model_defaults(monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    assert llm_client.get_base_url() == llm_client.DEFAULT_BASE_URL
    assert llm_client.get_model() == llm_client.DEFAULT_MODEL
