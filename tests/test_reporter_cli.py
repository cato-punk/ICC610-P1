"""Pruebas de extremo a extremo de la CLI del Reporter."""

from __future__ import annotations

from typer.testing import CliRunner

from reporter.cli import app

runner = CliRunner()


def test_cli_no_llm_writes_report(tmp_path, sample_repo):
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "--repo-root",
            str(sample_repo),
            "--output",
            str(output),
            "--no-llm",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output
    assert output.exists()
    assert "Auditoría de seguridad" in output.read_text(encoding="utf-8")


def test_cli_fail_on_high_exits_one(tmp_path, sample_repo):
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "--repo-root",
            str(sample_repo),
            "--output",
            str(output),
            "--no-llm",
            "--fail-on",
            "high",
            "--quiet",
        ],
    )
    assert result.exit_code == 1


def test_cli_fail_on_never_exits_zero(tmp_path, sample_repo):
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "--repo-root",
            str(sample_repo),
            "--output",
            str(output),
            "--no-llm",
            "--fail-on",
            "never",
            "--quiet",
        ],
    )
    assert result.exit_code == 0


def test_cli_invalid_fail_on_exits_two(sample_repo):
    result = runner.invoke(
        app, ["--repo-root", str(sample_repo), "--fail-on", "bogus", "--quiet"]
    )
    assert result.exit_code == 2


def test_cli_strict_llm_without_key_exits_two(tmp_path, sample_repo, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "--repo-root",
            str(sample_repo),
            "--output",
            str(output),
            "--strict-llm",
            "--quiet",
        ],
    )
    assert result.exit_code == 2


def test_cli_prints_summary_when_not_quiet(tmp_path, sample_repo):
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["--repo-root", str(sample_repo), "--output", str(output), "--no-llm"],
    )
    assert result.exit_code == 0
    assert "Reporte escrito en" in result.output
    assert "Modo determinista" in result.output


def test_main_invokes_app(monkeypatch):
    from reporter import cli

    called = {}
    monkeypatch.setattr(cli, "app", lambda *a, **k: called.setdefault("ok", True))
    cli.main()
    assert called.get("ok")


def test_module_entrypoint(tmp_path, monkeypatch):
    import runpy
    import sys

    import reporter  # noqa: F401 - asegura que el paquete esté importado

    sys.modules.pop("reporter.cli", None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reporter.cli",
            "--repo-root",
            str(tmp_path),
            "--output",
            str(tmp_path / "r.md"),
            "--no-llm",
            "--quiet",
        ],
    )
    try:
        runpy.run_module("reporter.cli", run_name="__main__")
    except SystemExit as exc:
        assert exc.code in (0, None)


def test_cli_rotate_aspects_creates_state(tmp_path, sample_repo):
    output = tmp_path / "report.md"
    state = tmp_path / "state.json"
    result = runner.invoke(
        app,
        [
            "--repo-root",
            str(sample_repo),
            "--output",
            str(output),
            "--no-llm",
            "--rotate-aspects",
            "--state-file",
            str(state),
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output
    assert state.exists()
