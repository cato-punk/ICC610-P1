"""Tests for the Grype CLI wrapper module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from analyzer.grype import (
    SEVERITIES,
    count_vulnerabilities,
    get_grype_version,
    scan_sbom,
    severity_counts,
)

# Verbatim shape of `grype version` output.
SAMPLE_VERSION_OUTPUT = """Application:         grype
Version:             0.120.0
BuildDate:           2026-01-01T00:00:00Z
GitCommit:           deadbeef
Platform:            windows/amd64
Syft Version:        v1.54.0
Supported DB Schema: 6
"""


def _mock_process(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


def _match(severity: str, name: str = "flask") -> dict:
    return {"vulnerability": {"id": "CVE-2023-0000", "severity": severity},
            "artifact": {"name": name}}


class TestGetGrypeVersion:
    @patch("analyzer.grype.subprocess.run")
    def test_parses_version_line(self, mock_run):
        mock_run.return_value = _mock_process(stdout=SAMPLE_VERSION_OUTPUT)
        assert get_grype_version() == "0.120.0"

    @patch("analyzer.grype.subprocess.run")
    def test_version_line_wins_over_syft_version_line(self, mock_run):
        """`grype version` also prints a 'Syft Version:' line; take the first."""
        mock_run.return_value = _mock_process(stdout=SAMPLE_VERSION_OUTPUT)
        assert get_grype_version() != "v1.54.0"

    @patch("analyzer.grype.subprocess.run")
    def test_falls_back_to_json(self, mock_run):
        mock_run.side_effect = [
            _mock_process(stdout="no structured version here"),
            _mock_process(stdout=json.dumps({"version": "0.99.0"})),
        ]
        assert get_grype_version() == "0.99.0"

    @patch("analyzer.grype.subprocess.run")
    def test_json_fallback_uses_dash_o_flag(self, mock_run):
        """Grype uses `-o json`; syft's `--format json` exits non-zero."""
        mock_run.side_effect = [
            _mock_process(stdout="unstructured"),
            _mock_process(stdout=json.dumps({"version": "0.99.0"})),
        ]
        get_grype_version()
        assert mock_run.call_args_list[1][0][0][-2:] == ["-o", "json"]

    @patch("analyzer.grype.subprocess.run")
    def test_falls_back_to_first_line(self, mock_run):
        mock_run.side_effect = [
            _mock_process(stdout="grype-raw-string"),
            _mock_process(returncode=1, stderr="nope"),
        ]
        assert get_grype_version() == "grype-raw-string"

    @patch("analyzer.grype.subprocess.run")
    def test_raises_on_failure(self, mock_run):
        mock_run.return_value = _mock_process(returncode=1, stderr="grype: not found")
        with pytest.raises(RuntimeError):
            get_grype_version()


class TestScanSbom:
    @patch("analyzer.grype.subprocess.run")
    def test_builds_sbom_command(self, mock_run, tmp_path: Path):
        mock_run.return_value = _mock_process(stdout='{"matches": []}')
        sbom = tmp_path / "repo.cdx.json"
        sbom.write_text("{}", encoding="utf-8")
        output = tmp_path / "out" / "repo.json"

        result = scan_sbom(sbom, output)

        assert result == output
        assert output.parent.exists()
        assert json.loads(output.read_text(encoding="utf-8")) == {"matches": []}

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "grype"
        assert cmd[1] == f"sbom:{sbom}"
        assert cmd[2:] == ["-o", "json"]

    @patch("analyzer.grype.subprocess.run")
    def test_raises_on_nonzero_exit(self, mock_run, tmp_path: Path):
        mock_run.return_value = _mock_process(returncode=1, stderr="unable to parse SBOM")
        sbom = tmp_path / "repo.cdx.json"
        sbom.write_text("{}", encoding="utf-8")
        with pytest.raises(RuntimeError):
            scan_sbom(sbom, tmp_path / "repo.json")

    @patch("analyzer.grype.subprocess.run")
    def test_error_message_includes_stdout(self, mock_run, tmp_path: Path):
        """Grype sometimes reports the real problem on stdout, not stderr."""
        mock_run.return_value = _mock_process(returncode=1, stdout="bad SBOM detail")
        sbom = tmp_path / "repo.cdx.json"
        sbom.write_text("{}", encoding="utf-8")
        with pytest.raises(RuntimeError, match="bad SBOM detail"):
            scan_sbom(sbom, tmp_path / "repo.json")


class TestCountVulnerabilities:
    def _write_report(self, tmp_path: Path, matches: list) -> Path:
        path = tmp_path / "report.json"
        path.write_text(json.dumps({"matches": matches}), encoding="utf-8")
        return path

    def test_counts_matches(self, tmp_path: Path):
        path = self._write_report(tmp_path, [_match("High"), _match("Low")])
        assert count_vulnerabilities(path) == 2

    def test_missing_matches_key_is_zero(self, tmp_path: Path):
        path = self._write_report(tmp_path, [])
        assert count_vulnerabilities(path) == 0

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            count_vulnerabilities(tmp_path / "missing.json")


class TestSeverityCounts:
    def _write_report(self, tmp_path: Path, matches: list) -> Path:
        path = tmp_path / "report.json"
        path.write_text(json.dumps({"matches": matches}), encoding="utf-8")
        return path

    def test_counts_by_severity(self, tmp_path: Path):
        path = self._write_report(tmp_path, [
            _match("Critical", "a"),
            _match("Critical", "b"),
            _match("High", "c"),
            _match("Low", "d"),
        ])
        counts = severity_counts(path)
        assert counts["Critical"] == 2
        assert counts["High"] == 1
        assert counts["Medium"] == 0
        assert counts["Low"] == 1
        assert counts["Negligible"] == 0

    def test_always_includes_every_severity(self, tmp_path: Path):
        """Stable key set so callers can render fixed columns."""
        path = self._write_report(tmp_path, [_match("High")])
        assert set(severity_counts(path)) == set(SEVERITIES)

    def test_no_matches_is_all_zero(self, tmp_path: Path):
        path = self._write_report(tmp_path, [])
        assert all(v == 0 for v in severity_counts(path).values())

    def test_unknown_severity_is_kept(self, tmp_path: Path):
        """An unexpected severity is surfaced, not silently dropped."""
        path = self._write_report(tmp_path, [_match("Bogus")])
        counts = severity_counts(path)
        assert counts["Bogus"] == 1
        assert counts["Critical"] == 0

    def test_match_without_vulnerability_key(self, tmp_path: Path):
        path = self._write_report(tmp_path, [{"artifact": {"name": "x"}}])
        counts = severity_counts(path)
        assert counts[""] == 1