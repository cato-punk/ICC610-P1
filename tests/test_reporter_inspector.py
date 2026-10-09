"""Pruebas del inspector determinista del Reporter."""

from __future__ import annotations

from reporter.repo_inspector import ASPECTS, collect_evidence


def _by_rule(result, rule_id: str):
    for finding in result.findings:
        if finding.finding_id == f"{finding.aspect}:{rule_id}":
            return finding
    return None


def _evidence(result, evidence_id: str):
    for item in result.evidence:
        if item.evidence_id == evidence_id:
            return item
    return None


def test_all_aspects_present(sample_repo):
    result = collect_evidence(sample_repo)
    assert result.aspects == ASPECTS
    assert result.files_scanned > 0


def test_deterministic(sample_repo):
    first = collect_evidence(sample_repo)
    second = collect_evidence(sample_repo)
    assert [e.model_dump() for e in first.evidence] == [
        e.model_dump() for e in second.evidence
    ]
    assert [f.model_dump() for f in first.findings] == [
        f.model_dump() for f in second.findings
    ]


def test_evidence_has_file_and_line(sample_repo):
    result = collect_evidence(sample_repo)
    assert result.evidence
    for item in result.evidence:
        assert item.file
        assert item.start_line >= 1
        assert item.snippet_sha256
        assert item.evidence_id


def test_findings_reference_existing_evidence(sample_repo):
    result = collect_evidence(sample_repo)
    valid_ids = {e.evidence_id for e in result.evidence}
    assert result.findings
    for finding in result.findings:
        assert finding.evidence_ids
        assert set(finding.evidence_ids) <= valid_ids


def test_secret_redacted(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "secret-quoted") is not None
    all_snippets = "\n".join(e.snippet for e in result.evidence)
    assert "sk-1234567890abcdef1234" not in all_snippets
    assert any("[REDACTED]" in e.snippet for e in result.evidence)


def test_committed_env_detected(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "secret-committed-env") is not None


def test_unpinned_action_with_location(sample_repo):
    result = collect_evidence(sample_repo)
    finding = _by_rule(result, "sc-unpinned-action")
    assert finding is not None
    evidence = _evidence(result, finding.evidence_ids[0])
    assert evidence is not None
    assert evidence.file == ".github/workflows/ci.yml"
    assert evidence.start_line >= 1


def test_pinned_sha_action_not_flagged(sample_repo):
    pinned = sample_repo / ".github" / "workflows" / "pinned.yml"
    pinned.write_text(
        "name: Pinned\non: push\npermissions: read-all\njobs:\n  b:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
        encoding="utf-8",
    )
    result = collect_evidence(sample_repo)
    finding = _by_rule(result, "sc-unpinned-action")
    flagged = {
        _evidence(result, eid).file for eid in finding.evidence_ids
    }
    assert "pinned.yml" not in flagged
    assert ".github/workflows/ci.yml" in flagged


def test_secret_placeholders_not_flagged(sample_repo):
    (sample_repo / "config.py").write_text(
        'API_KEY = "[REDACTED]"\n'
        'PASSWORD = "changeme123"\n'
        'GITHUB_TOKEN = "ghp_your_token_here"\n',
        encoding="utf-8",
    )
    result = collect_evidence(sample_repo)
    finding = _by_rule(result, "secret-quoted")
    flagged = {_evidence(result, eid).file for eid in finding.evidence_ids}
    assert "config.py" not in flagged


def test_env_placeholder_not_flagged(sample_repo):
    (sample_repo / ".env").write_text("TOKEN=[REDACTED]\n", encoding="utf-8")
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "secret-env-file") is None


def test_tests_dir_excluded(sample_repo):
    tests_dir = sample_repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "fixture.py").write_text("os.system('x')\n", encoding="utf-8")
    result = collect_evidence(sample_repo)
    assert not any(item.file.startswith("tests/") for item in result.evidence)


def test_reports_dir_excluded(sample_repo):
    reports = sample_repo / "reports"
    reports.mkdir()
    (reports / "security_audit_report.md").write_text(
        "chmod 777 /tmp/old\n", encoding="utf-8"
    )
    result = collect_evidence(sample_repo)
    assert not any(item.file.startswith("reports/") for item in result.evidence)


def test_engine_self_excluded(sample_repo):
    engine = sample_repo / "src" / "reporter"
    engine.mkdir(parents=True)
    (engine / "rules.py").write_text('X = "chmod 777 /tmp/x"\n', encoding="utf-8")
    result = collect_evidence(sample_repo)
    assert not any(item.file.startswith("src/reporter") for item in result.evidence)


def test_command_injection(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "ci-shell-true") is not None
    assert _by_rule(result, "ci-os-system") is not None
    assert _by_rule(result, "ci-dynamic-eval") is not None


def test_network_requests(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "net-verify-false") is not None


def test_file_permissions(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "fp-world-writable") is not None


def test_sandbox_escape(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "sb-privileged-op") is not None


def test_github_token_scope(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "tok-write-all") is not None
    assert _by_rule(result, "tok-persist-credentials") is not None


def test_output_injection(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "out-script-injection") is not None


def test_workflow_security(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "ws-pull-request-target") is not None
    assert _by_rule(result, "ws-missing-permissions") is not None


def test_docker_unpinned(sample_repo):
    result = collect_evidence(sample_repo)
    assert _by_rule(result, "sc-docker-unpinned") is not None


def test_excluded_dirs(sample_repo):
    result = collect_evidence(sample_repo)
    assert not any(".venv" in item.file for item in result.evidence)
    assert not any(item.file.startswith("data/raw") for item in result.evidence)


def test_excluded_data_raw(sample_repo):
    raw = sample_repo / "data" / "raw"
    raw.mkdir(parents=True)
    (raw / "leak.py").write_text("subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    result = collect_evidence(sample_repo)
    assert not any(item.file.startswith("data/raw") for item in result.evidence)


def test_read_text_skips_large_and_binary(tmp_path):
    from reporter import repo_inspector

    large = tmp_path / "large.py"
    large.write_text("x" * 20, encoding="utf-8")
    assert repo_inspector._read_text(large, max_bytes=5) is None

    binary = tmp_path / "bin.py"
    binary.write_bytes(b"abc\x00def")
    assert repo_inspector._read_text(binary, max_bytes=1000) is None


def test_collect_skips_unreadable_files(sample_repo):
    (sample_repo / "binary.py").write_bytes(b"\x00\x01\x02")
    result = collect_evidence(sample_repo)
    assert not any(item.file == "binary.py" for item in result.evidence)


def test_read_text_oserror(tmp_path, monkeypatch):
    from pathlib import Path

    from reporter import repo_inspector

    path = tmp_path / "x.py"
    path.write_text("a", encoding="utf-8")

    def boom(self):
        raise OSError("nope")

    monkeypatch.setattr(Path, "read_bytes", boom)
    assert repo_inspector._read_text(path, max_bytes=100) is None


def test_aspect_filter(sample_repo):
    result = collect_evidence(sample_repo, aspects=["secret-handling"])
    assert result.aspects == ["secret-handling"]
    assert result.findings
    assert all(f.aspect == "secret-handling" for f in result.findings)
    assert all(e.aspect == "secret-handling" for e in result.evidence)


def test_ordered_json(sample_repo):
    result = collect_evidence(sample_repo)
    data = result.to_ordered_json()
    assert data["inspector_version"]
    assert isinstance(data["findings"], list)
    assert isinstance(data["evidence"], list)
    severities = [f["severity"] for f in data["findings"]]
    expected_order = ["critical", "high", "medium", "low", "info"]
    assert severities == sorted(severities, key=expected_order.index)
