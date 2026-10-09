"""Tests for CLI helpers (sorting and limiting repositories)."""

from __future__ import annotations

import json

import pytest

from miner.cli import _apply_sort_limit
from miner.github import GitHubRepo


def make_repo(name: str, stars: int = 0, forks: int = 0, size: int = 0, pushed_at: str = "") -> GitHubRepo:
    return GitHubRepo(
        name=name,
        clone_url=f"https://github.com/o/{name}.git",
        languages_url=f"https://api.github.com/repos/o/{name}/languages",
        default_branch="main",
        stargazers_count=stars,
        forks_count=forks,
        size=size,
        pushed_at=pushed_at,
    )


class TestApplySortLimit:
    def test_no_options_returns_unchanged(self):
        repos = [make_repo("a", stars=5), make_repo("b", stars=10)]
        assert _apply_sort_limit(repos, None, None) == repos

    def test_limit_only_takes_top_by_stars(self):
        repos = [make_repo("a", stars=5), make_repo("b", stars=10), make_repo("c", stars=1)]
        result = _apply_sort_limit(repos, 2, None)
        assert [r.name for r in result] == ["b", "a"]

    def test_sort_by_stars_descending(self):
        repos = [make_repo("a", stars=5), make_repo("b", stars=10), make_repo("c", stars=1)]
        result = _apply_sort_limit(repos, None, "stars")
        assert [r.name for r in result] == ["b", "a", "c"]

    def test_sort_by_name_ascending(self):
        repos = [make_repo("banana"), make_repo("apple"), make_repo("cherry")]
        result = _apply_sort_limit(repos, None, "name")
        assert [r.name for r in result] == ["apple", "banana", "cherry"]

    def test_sort_by_forks_and_limit(self):
        repos = [make_repo("a", forks=2), make_repo("b", forks=9), make_repo("c", forks=4)]
        result = _apply_sort_limit(repos, 2, "forks")
        assert [r.name for r in result] == ["b", "c"]

    def test_sort_by_pushed_at_strings(self):
        repos = [
            make_repo("old", pushed_at="2020-01-01T00:00:00Z"),
            make_repo("new", pushed_at="2025-06-01T00:00:00Z"),
        ]
        result = _apply_sort_limit(repos, None, "pushed")
        assert [r.name for r in result] == ["new", "old"]

    def test_limit_larger_than_list(self):
        repos = [make_repo("a", stars=1), make_repo("b", stars=2)]
        result = _apply_sort_limit(repos, 50, None)
        assert [r.name for r in result] == ["b", "a"]

    def test_unknown_criterion_raises(self):
        with pytest.raises(ValueError):
            _apply_sort_limit([make_repo("a")], 10, "wat")

    def test_empty_list(self):
        assert _apply_sort_limit([], 10, "stars") == []
        assert _apply_sort_limit([], None, None) == []


class TestNormalizeLanguage:
    def test_aliases_c_and_csharp(self):
        from miner.cli import _normalize_language

        assert _normalize_language("C++") == "cpp"
        assert _normalize_language("C#") == "csharp"
        assert _normalize_language("Python") == "python"
        assert _normalize_language("c") == "c"
        assert _normalize_language("Kotlin") == "kotlin"


class TestAnalyzeRepoResilience:
    """_analyze_repo should keep going when one language fails."""

    def test_analyzed_when_one_language_fails(self, tmp_path, monkeypatch):
        from miner.cli import _analyze_repo
        from miner.models import Finding, RepoStatus

        def fake_langs(url):
            return ["JavaScript", "Swift"]

        def fake_clone(url, target):
            target.mkdir(parents=True, exist_ok=True)

        def fake_create(lang, source, db_dir):
            db_dir.mkdir(parents=True, exist_ok=True)
            if lang == "swift":
                raise RuntimeError("autobuild failed (no Xcode)")
            return db_dir

        def fake_analyze(db_dir, lang, sarif_path, packs_root):
            sarif_path.write_text("{}")

        def fake_parse(sarif_path):
            return [
                Finding(
                    rule_id="js/xss",
                    severity="warning",
                    message="xss",
                    file="app.js",
                    start_line=1,
                )
            ]

        monkeypatch.setattr("miner.cli.fetch_languages", fake_langs)
        monkeypatch.setattr("miner.cli.clone_repo", fake_clone)
        monkeypatch.setattr("miner.cli.create_database", fake_create)
        monkeypatch.setattr("miner.cli.run_analysis", fake_analyze)
        monkeypatch.setattr("miner.cli.parse_sarif", fake_parse)

        result = _analyze_repo(
            "mozilla", "send", "https://github.com/mozilla/send.git",
            "https://api.github.com/repos/mozilla/send/languages", tmp_path,
        )

        assert result.status == RepoStatus.ANALYZED
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "js/xss"
        assert "swift" in (result.error_message or "")

    def test_database_failed_when_all_fail(self, tmp_path, monkeypatch):
        from miner.cli import _analyze_repo
        from miner.models import RepoStatus

        def fake_langs(url):
            return ["Swift"]

        def fake_clone(url, target):
            target.mkdir(parents=True, exist_ok=True)

        def fake_create(lang, source, db_dir):
            db_dir.mkdir(parents=True, exist_ok=True)
            raise RuntimeError("autobuild failed")

        monkeypatch.setattr("miner.cli.fetch_languages", fake_langs)
        monkeypatch.setattr("miner.cli.clone_repo", fake_clone)
        monkeypatch.setattr("miner.cli.create_database", fake_create)

        result = _analyze_repo(
            "mozilla", "send", "https://github.com/mozilla/send.git",
            "https://api.github.com/repos/mozilla/send/languages", tmp_path,
        )

        assert result.status == RepoStatus.DATABASE_FAILED
        assert "swift" in (result.error_message or "")

    def test_analysis_failed_when_all_analyses_fail(self, tmp_path, monkeypatch):
        from miner.cli import _analyze_repo
        from miner.models import RepoStatus

        def fake_langs(url):
            return ["JavaScript"]

        def fake_clone(url, target):
            target.mkdir(parents=True, exist_ok=True)

        def fake_create(lang, source, db_dir):
            db_dir.mkdir(parents=True, exist_ok=True)
            return db_dir

        def fake_analyze(db_dir, lang, sarif_path, packs_root):
            raise RuntimeError("analysis crashed")

        monkeypatch.setattr("miner.cli.fetch_languages", fake_langs)
        monkeypatch.setattr("miner.cli.clone_repo", fake_clone)
        monkeypatch.setattr("miner.cli.create_database", fake_create)
        monkeypatch.setattr("miner.cli.run_analysis", fake_analyze)

        result = _analyze_repo(
            "mozilla", "pdf", "https://github.com/mozilla/pdf.js.git",
            "https://api.github.com/repos/mozilla/pdf.js/languages", tmp_path,
        )

        assert result.status == RepoStatus.ANALYSIS_FAILED
        assert "javascript" in (result.error_message or "")

    def test_cpp_maps_to_codeql_language(self, tmp_path, monkeypatch):
        from miner.cli import _analyze_repo
        from miner.models import RepoStatus

        tried: list[str] = []

        def fake_langs(url):
            return ["C++", "Python"]

        def fake_clone(url, target):
            target.mkdir(parents=True, exist_ok=True)

        def fake_create(lang, source, db_dir):
            tried.append(lang)
            db_dir.mkdir(parents=True, exist_ok=True)
            raise RuntimeError("no build system")

        monkeypatch.setattr("miner.cli.fetch_languages", fake_langs)
        monkeypatch.setattr("miner.cli.clone_repo", fake_clone)
        monkeypatch.setattr("miner.cli.create_database", fake_create)

        result = _analyze_repo(
            "mozilla", "deepspeech", "https://github.com/mozilla/DeepSpeech.git",
            "https://api.github.com/repos/mozilla/DeepSpeech/languages", tmp_path,
        )

        assert result.status == RepoStatus.DATABASE_FAILED
        # GitHub's "C++" must be mapped to CodeQL's "cpp" and tried
        assert "cpp" in tried
        assert "python" in tried


class TestBuildGrypeResult:
    def _sbom(self, tmp_path):
        sbom = tmp_path / "repo.cdx.json"
        sbom.write_text("{}", encoding="utf-8")
        return sbom

    def test_missing_sbom_is_skipped_not_failed(self, tmp_path):
        from miner.cli import _build_grype_result
        from miner.models import GrypeStatus

        result = _build_grype_result(
            "mozilla", "send", tmp_path / "absent.cdx.json", tmp_path / "send.json", "0.120.0",
        )

        assert result.status is GrypeStatus.SKIPPED
        assert "not found" in (result.error_message or "")
        assert result.vulnerabilities == 0

    def test_vulnerabilities_found_is_success(self, tmp_path, monkeypatch):
        from miner.cli import _build_grype_result
        from miner.models import GrypeStatus

        monkeypatch.setattr("miner.cli.scan_sbom", lambda s, o: o)
        monkeypatch.setattr("miner.cli.count_vulnerabilities", lambda p: 3)
        monkeypatch.setattr(
            "miner.cli.severity_counts",
            lambda p: {"Critical": 1, "High": 2, "Medium": 0, "Low": 0, "Negligible": 0},
        )

        result = _build_grype_result(
            "mozilla", "send", self._sbom(tmp_path), tmp_path / "send.json", "0.120.0",
        )

        assert result.status is GrypeStatus.SUCCESS
        assert result.vulnerabilities == 3
        assert result.severity_counts["Critical"] == 1

    def test_clean_scan_is_no_vulnerabilities(self, tmp_path, monkeypatch):
        from miner.cli import _build_grype_result
        from miner.models import GrypeStatus

        monkeypatch.setattr("miner.cli.scan_sbom", lambda s, o: o)
        monkeypatch.setattr("miner.cli.count_vulnerabilities", lambda p: 0)
        monkeypatch.setattr(
            "miner.cli.severity_counts",
            lambda p: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0},
        )

        result = _build_grype_result(
            "mozilla", "send", self._sbom(tmp_path), tmp_path / "send.json", "0.120.0",
        )

        assert result.status is GrypeStatus.NO_VULNERABILITIES

    def test_scan_exception_is_recorded_not_raised(self, tmp_path, monkeypatch):
        from miner.cli import _build_grype_result
        from miner.models import GrypeStatus

        def boom(sbom, out):
            raise RuntimeError("grype crashed")

        monkeypatch.setattr("miner.cli.scan_sbom", boom)

        result = _build_grype_result(
            "mozilla", "send", self._sbom(tmp_path), tmp_path / "send.json", "0.120.0",
        )

        assert result.status is GrypeStatus.FAILED
        assert "grype crashed" in (result.error_message or "")


class TestGrypeCommand:
    """End-to-end checks on `miner grype`.

    The console output is asserted implicitly: Rich raises MarkupError on an
    unbalanced closing tag such as 'reports written to x[/]', which would
    surface here as a non-zero exit code and a captured exception.
    """

    def _run(self, args, monkeypatch, repos=None, severity=None, count=2):
        from typer.testing import CliRunner
        from miner.cli import app

        monkeypatch.setattr("miner.cli._grype_available", lambda: "0.120.0")
        monkeypatch.setattr("miner.cli.fetch_repos", lambda org: repos or [make_repo("send", stars=10)])

        def fake_scan(sbom, out):
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text('{"matches": []}', encoding="utf-8")
            return out

        monkeypatch.setattr("miner.cli.scan_sbom", fake_scan)
        monkeypatch.setattr("miner.cli.count_vulnerabilities", lambda p: count)
        monkeypatch.setattr("miner.cli.severity_counts", lambda p: severity or {
            "Critical": 1, "High": 1, "Medium": 0, "Low": 0, "Negligible": 0,
        })
        return CliRunner().invoke(app, ["grype", *args])

    def test_happy_path_writes_report(self, tmp_path, monkeypatch):
        sboms = tmp_path / "sboms"
        sboms.mkdir()
        (sboms / "send.cdx.json").write_text("{}", encoding="utf-8")
        out = tmp_path / "grype-out"

        result = self._run(
            ["--organization", "mozilla", "--sbom-dir", str(sboms), "--output-dir", str(out)],
            monkeypatch,
        )

        assert result.exit_code == 0, result.exception
        assert result.exception is None
        report = out / "grype-report.json"
        assert report.exists()
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["organization"] == "mozilla"
        assert data["grype_version"] == "0.120.0"
        assert data["summary"]["vulnerabilities"] == 2
        assert data["summary"]["severity_counts"]["Critical"] == 1
        assert data["repositories"][0]["full_name"] == "mozilla/send"

    def test_missing_sbom_is_skipped_and_not_fatal(self, tmp_path, monkeypatch):
        sboms = tmp_path / "sboms"
        sboms.mkdir()
        out = tmp_path / "grype-out"

        result = self._run(
            ["--organization", "mozilla", "--sbom-dir", str(sboms), "--output-dir", str(out)],
            monkeypatch,
        )

        assert result.exit_code == 0, result.exception
        data = json.loads((out / "grype-report.json").read_text(encoding="utf-8"))
        assert data["summary"]["skipped"] == 1
        assert data["summary"]["failed"] == 0

    def test_all_failed_exits_nonzero(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from miner.cli import app

        def boom(sbom, out):
            raise RuntimeError("grype crashed")

        monkeypatch.setattr("miner.cli._grype_available", lambda: "0.120.0")
        monkeypatch.setattr("miner.cli.fetch_repos", lambda org: [make_repo("send")])
        monkeypatch.setattr("miner.cli.scan_sbom", boom)
        sboms = tmp_path / "sboms"
        sboms.mkdir()
        (sboms / "send.cdx.json").write_text("{}", encoding="utf-8")

        result = CliRunner().invoke(app, [
            "grype", "--organization", "mozilla",
            "--sbom-dir", str(sboms), "--output-dir", str(tmp_path / "out"),
        ])

        assert result.exit_code == 1

    def test_respects_limit_and_sort_by(self, tmp_path, monkeypatch):
        sboms = tmp_path / "sboms"
        sboms.mkdir()
        for name in ("a", "b", "c"):
            (sboms / f"{name}.cdx.json").write_text("{}", encoding="utf-8")
        out = tmp_path / "grype-out"
        repos = [make_repo("a", stars=1), make_repo("b", stars=99), make_repo("c", stars=50)]

        result = self._run(
            ["--organization", "mozilla", "--limit", "2", "--sort-by", "stars",
             "--sbom-dir", str(sboms), "--output-dir", str(out)],
            monkeypatch,
            repos=repos,
        )

        assert result.exit_code == 0, result.exception
        data = json.loads((out / "grype-report.json").read_text(encoding="utf-8"))
        assert data["summary"]["repositories"] == 2
        assert [r["full_name"] for r in data["repositories"]] == ["mozilla/b", "mozilla/c"]

    def test_missing_sbom_dir_exits_one(self, tmp_path, monkeypatch):
        result = self._run(
            ["--organization", "mozilla", "--sbom-dir", str(tmp_path / "absent")],
            monkeypatch,
        )
        assert result.exit_code == 1

    def test_no_target_exits_one(self, monkeypatch):
        result = self._run([], monkeypatch)
        assert result.exit_code == 1

    def test_unknown_sort_by_exits_one(self, tmp_path, monkeypatch):
        sboms = tmp_path / "sboms"
        sboms.mkdir()
        result = self._run(
            ["--organization", "mozilla", "--sort-by", "bogus", "--sbom-dir", str(sboms)],
            monkeypatch,
        )
        assert result.exit_code == 1