"""Tests for GitHub API module."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from miner.github import (
    GitHubRepo,
    _find_dotenv,
    _get_token,
    _load_dotenv,
    _parse_dotenv,
    fetch_languages,
    fetch_repos,
)


class TestDotenv:
    def test_finds_env_in_project_root(self, tmp_path: Path, monkeypatch):
        root = tmp_path / "project"
        (root / "miner").mkdir(parents=True)
        (root / ".env").write_text("GITHUB_TOKEN=from-root\n", encoding="utf-8")
        monkeypatch.setattr("miner.github.__file__", str(root / "miner" / "github.py"))

        assert _find_dotenv() == root / ".env"

    def test_walks_up_from_nested_cwd(self, tmp_path: Path, monkeypatch):
        root = tmp_path / "project"
        nested = root / "data" / "repos"
        nested.mkdir(parents=True)
        (root / ".env").write_text("GITHUB_TOKEN=x\n", encoding="utf-8")
        # Package is installed in site-packages, so only cwd can find the file.
        monkeypatch.setattr(
            "miner.github.__file__", str(tmp_path / "site-packages" / "miner" / "github.py")
        )
        monkeypatch.chdir(nested)

        assert _find_dotenv() == root / ".env"

    def test_returns_none_when_absent(self, tmp_path: Path, monkeypatch):
        package = tmp_path / "site-packages" / "miner"
        package.mkdir(parents=True)
        monkeypatch.setattr("miner.github.__file__", str(package / "github.py"))
        monkeypatch.chdir(tmp_path)

        assert _find_dotenv() is None

    def test_parse_handles_comments_quotes_and_blanks(self, tmp_path: Path):
        env = tmp_path / ".env"
        env.write_text(
            "# a comment\n"
            "\n"
            "GITHUB_TOKEN='ghp_abc'\n"
            'OTHER_TOKEN="quoted value"\n'
            "EMPTY=\n"
            "MALFORMED_LINE\n"
            "WITH_EQUALS=a=b=c\n",
            encoding="utf-8",
        )

        assert _parse_dotenv(env) == {
            "GITHUB_TOKEN": "ghp_abc",
            "OTHER_TOKEN": "quoted value",
            "EMPTY": "",
            "WITH_EQUALS": "a=b=c",
        }

    def test_load_populates_environment(self, tmp_path: Path, monkeypatch):
        root = tmp_path / "project"
        (root / "miner").mkdir(parents=True)
        (root / ".env").write_text("GITHUB_TOKEN=from-root\nNEW_VAR=new-value\n", encoding="utf-8")
        monkeypatch.setattr("miner.github.__file__", str(root / "miner" / "github.py"))
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("NEW_VAR", raising=False)

        _load_dotenv()

        assert os.environ["GITHUB_TOKEN"] == "from-root"
        assert os.environ["NEW_VAR"] == "new-value"

    def test_existing_environment_wins(self, tmp_path: Path, monkeypatch):
        root = tmp_path / "project"
        (root / "miner").mkdir(parents=True)
        (root / ".env").write_text("GITHUB_TOKEN=from-root\n", encoding="utf-8")
        monkeypatch.setattr("miner.github.__file__", str(root / "miner" / "github.py"))
        monkeypatch.setenv("GITHUB_TOKEN", "from-shell")

        _load_dotenv()

        assert os.environ["GITHUB_TOKEN"] == "from-shell"

    def test_missing_env_is_a_noop(self, tmp_path: Path, monkeypatch):
        package = tmp_path / "site-packages" / "miner"
        package.mkdir(parents=True)
        monkeypatch.setattr("miner.github.__file__", str(package / "github.py"))
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        _load_dotenv()

        assert "GITHUB_TOKEN" not in os.environ

    def test_get_token_raises_helpful_error(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        with pytest.raises(RuntimeError, match=r"\.env"):
            _get_token()

    def test_get_token_returns_env_value(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_xyz")

        assert _get_token() == "ghp_xyz"


class TestFetchRepos:
    @patch("miner.github.requests.get")
    def test_single_page(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"name": "repo1", "clone_url": "https://github.com/org/repo1.git",
             "languages_url": "https://api.github.com/repos/org/repo1/languages",
             "default_branch": "main"},
            {"name": "repo2", "clone_url": "https://github.com/org/repo2.git",
             "languages_url": "https://api.github.com/repos/org/repo2/languages",
             "default_branch": "main"},
        ]
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        with patch("miner.github._get_token", return_value="fake-token"):
            repos = fetch_repos("test-org")

        assert len(repos) == 2
        assert repos[0].name == "repo1"
        assert repos[1].name == "repo2"
        assert mock_get.call_count == 1

    @patch("miner.github.requests.get")
    def test_pagination(self, mock_get):
        page1_response = MagicMock()
        page1_response.json.return_value = [
            {"name": f"repo{i}", "clone_url": f"https://github.com/org/repo{i}.git",
             "languages_url": f"https://api.github.com/repos/org/repo{i}/languages",
             "default_branch": "main"}
            for i in range(100)
        ]
        page1_response.raise_for_status = MagicMock()

        page2_response = MagicMock()
        page2_response.json.return_value = [
            {"name": "repo100", "clone_url": "https://github.com/org/repo100.git",
             "languages_url": "https://api.github.com/repos/org/repo100/languages",
             "default_branch": "main"},
        ]
        page2_response.raise_for_status = MagicMock()

        mock_get.side_effect = [page1_response, page2_response]

        with patch("miner.github._get_token", return_value="fake-token"):
            repos = fetch_repos("test-org")

        assert len(repos) == 101
        assert mock_get.call_count == 2

    @patch("miner.github.requests.get")
    def test_empty_org(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        with patch("miner.github._get_token", return_value="fake-token"):
            repos = fetch_repos("empty-org")

        assert repos == []

    @patch("miner.github.requests.get")
    def test_populates_metadata_fields(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"name": "repo1", "clone_url": "https://github.com/org/repo1.git",
             "languages_url": "https://api.github.com/repos/org/repo1/languages",
             "default_branch": "main",
             "stargazers_count": 42, "forks_count": 7, "open_issues_count": 3,
             "size": 1000, "created_at": "2020-01-01T00:00:00Z",
             "updated_at": "2021-01-01T00:00:00Z", "pushed_at": "2022-01-01T00:00:00Z"},
        ]
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        with patch("miner.github._get_token", return_value="fake-token"):
            repos = fetch_repos("test-org")

        repo = repos[0]
        assert repo.stargazers_count == 42
        assert repo.forks_count == 7
        assert repo.open_issues_count == 3
        assert repo.size == 1000
        assert repo.created_at == "2020-01-01T00:00:00Z"
        assert repo.updated_at == "2021-01-01T00:00:00Z"
        assert repo.pushed_at == "2022-01-01T00:00:00Z"


class TestFetchLanguages:
    @patch("miner.github._get_token", return_value="fake-token")
    @patch("miner.github.requests.get")
    def test_fetch_languages(self, mock_get, mock_token):
        mock_response = MagicMock()
        mock_response.json.return_value = {"Python": 1000, "JavaScript": 500}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        langs = fetch_languages("https://api.github.com/repos/org/repo/languages")
        assert langs == ["Python", "JavaScript"]


class TestGitHubRepo:
    def test_dataclass(self):
        repo = GitHubRepo(
            name="test",
            clone_url="https://github.com/org/test.git",
            languages_url="https://api.github.com/repos/org/test/languages",
            default_branch="main",
        )
        assert repo.name == "test"
        assert repo.default_branch == "main"
