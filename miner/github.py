"""GitHub API interaction module."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests


def _find_dotenv() -> Path | None:
    """Locate the project ``.env`` file, or ``None`` if there is none.

    Walks up from the installed package location first, so an editable install
    or a source checkout always resolves to the project root no matter where
    the command is invoked from. Falls back to walking up from the current
    working directory, which covers non-editable installs where the package
    lives in ``site-packages``.
    """
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
    """Parse ``KEY=VALUE`` pairs from a ``.env`` file.

    Blank lines and ``#`` comments are ignored. Values may be quoted with
    single or double quotes, and may themselves contain ``=``.
    """
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def _load_dotenv() -> None:
    """Populate ``os.environ`` from the project root ``.env`` file.

    Existing environment variables always win, so an explicitly exported
    variable or a ``.env`` closer to the caller overrides the project file.
    """
    env_file = _find_dotenv()
    if env_file is None:
        return
    for key, value in _parse_dotenv(env_file).items():
        os.environ.setdefault(key, value)


_load_dotenv()


@dataclass
class GitHubRepo:
    name: str
    clone_url: str
    languages_url: str
    default_branch: str
    stargazers_count: int = 0
    forks_count: int = 0
    open_issues_count: int = 0
    size: int = 0
    created_at: str = ""
    updated_at: str = ""
    pushed_at: str = ""
    fork: bool = False
    archived: bool = False
    language: str = ""
    full_name: str = ""
    html_url: str = ""


def _get_token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError(
            "GITHUB_TOKEN is not set. Create a .env file in the project root with "
            "GITHUB_TOKEN=<your token> (see .env.example), or export the variable."
        )
    return token


def _make_headers() -> dict[str, str]:
    return {
        "Authorization": f"token {_get_token()}",
        "Accept": "application/vnd.github+json",
    }


def fetch_repos(organization: str) -> list[GitHubRepo]:
    repos: list[GitHubRepo] = []
    url = f"https://api.github.com/orgs/{organization}/repos"
    params = {"per_page": 100, "page": 1, "type": "public"}

    while True:
        response = requests.get(url, headers=_make_headers(), params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        if not data:
            break
        for repo in data:
            repos.append(
                GitHubRepo(
                    name=repo["name"],
                    clone_url=repo["clone_url"],
                    languages_url=repo["languages_url"],
                    default_branch=repo.get("default_branch", "main"),
                    stargazers_count=repo.get("stargazers_count") or 0,
                    forks_count=repo.get("forks_count") or 0,
                    open_issues_count=repo.get("open_issues_count") or 0,
                    size=repo.get("size") or 0,
                    created_at=repo.get("created_at") or "",
                    updated_at=repo.get("updated_at") or "",
                    pushed_at=repo.get("pushed_at") or "",
                    fork=bool(repo.get("fork")),
                    archived=bool(repo.get("archived")),
                    language=repo.get("language") or "",
                    full_name=repo.get("full_name") or "",
                    html_url=repo.get("html_url") or "",
                )
            )
        if len(data) < 100:
            break
        params["page"] += 1

    return repos


def fetch_languages(languages_url: str) -> list[str]:
    response = requests.get(languages_url, headers=_make_headers(), timeout=30)
    response.raise_for_status()
    return list(response.json().keys())
