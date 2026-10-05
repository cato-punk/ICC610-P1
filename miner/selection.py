"""Criterio de selección reproducible de repositorios de la organización."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .github import GitHubRepo

SUPPORTED_CODEQL_LANGUAGES = {
    "python", "java", "javascript", "typescript",
    "csharp", "cpp", "c", "go", "ruby", "swift", "rust",
}

# GitHub reports some languages with different names than CodeQL uses.
LANGUAGE_NAME_ALIASES = {"c++": "cpp", "c#": "csharp"}

DEFAULT_SORT_BY = "stars"

SORT_CRITERIA = {
    "stars": "stargazers_count",
    "forks": "forks_count",
    "issues": "open_issues_count",
    "size": "size",
    "pushed": "pushed_at",
    "updated": "updated_at",
    "created": "created_at",
    "name": "name",
}


def normalize_language(language: str) -> str:
    """Map a GitHub API language name to a CodeQL language id (lowercase)."""
    return LANGUAGE_NAME_ALIASES.get(language.lower(), language.lower())


def apply_sort_limit(repos, limit: int | None, sort_by: str | None):
    """Sort descending by criterion ('name' ascending) and truncate to limit."""
    if limit is None and sort_by is None:
        return repos
    criterion = sort_by or DEFAULT_SORT_BY
    field = SORT_CRITERIA.get(criterion)
    if field is None:
        raise ValueError(
            f"Unknown --sort-by criterion '{criterion}'. "
            f"Use one of: {', '.join(sorted(SORT_CRITERIA))}."
        )
    ordered = sorted(repos, key=lambda r: getattr(r, field), reverse=field != "name")
    return ordered[:limit] if limit is not None else ordered


@dataclass
class SelectionCriteria:
    """Reglas que definen qué repositorios entran al estudio."""

    organization: str
    exclude_forks: bool = True
    exclude_archived: bool = True
    require_codeql_language: bool = True
    max_size_kb: int | None = 100_000        # ~100 MB
    pushed_within_days: int | None = 730     # ~2 años
    sort_by: str = DEFAULT_SORT_BY
    max_repos: int = 40


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def rejection_reason(
    repo: GitHubRepo, criteria: SelectionCriteria, now: datetime
) -> str | None:
    """Return why a repo is rejected, or None if it is eligible."""
    if criteria.exclude_forks and repo.fork:
        return "fork"
    if criteria.exclude_archived and repo.archived:
        return "archived"
    if repo.size <= 0:
        return "empty"
    if criteria.max_size_kb is not None and repo.size > criteria.max_size_kb:
        return "too_large"
    if criteria.require_codeql_language:
        if not repo.language:
            return "no_primary_language"
        if normalize_language(repo.language) not in SUPPORTED_CODEQL_LANGUAGES:
            return "unsupported_language"
    if criteria.pushed_within_days is not None:
        pushed = _parse_date(repo.pushed_at)
        if pushed is None or pushed < now - timedelta(days=criteria.pushed_within_days):
            return "inactive"
    return None


def filter_repos(
    repos: list[GitHubRepo],
    criteria: SelectionCriteria,
    now: datetime | None = None,
) -> tuple[list[GitHubRepo], dict[str, list[str]]]:
    """Split repos into (eligible, {reason: [names]})."""
    now = now or datetime.now(timezone.utc)
    eligible: list[GitHubRepo] = []
    rejected: dict[str, list[str]] = defaultdict(list)
    for repo in repos:
        reason = rejection_reason(repo, criteria, now)
        if reason is None:
            eligible.append(repo)
        else:
            rejected[reason].append(repo.name)
    return eligible, dict(rejected)


def write_manifest(
    path: Path,
    criteria: SelectionCriteria,
    total: int,
    eligible: int,
    selected: list[GitHubRepo],
    rejected: dict[str, list[str]],
) -> None:
    """Persist the criteria and the candidate list so the sample is reproducible."""
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "criteria": asdict(criteria),
        "total_in_organization": total,
        "eligible_after_filters": eligible,
        "candidates": [
            {
                "name": r.name,
                "full_name": r.full_name,
                "url": r.html_url,
                "primary_language": r.language,
                "stars": r.stargazers_count,
                "forks": r.forks_count,
                "size_kb": r.size,
                "pushed_at": r.pushed_at,
                "default_branch": r.default_branch,
            }
            for r in selected
        ],
        "rejected_summary": {k: len(v) for k, v in sorted(rejected.items())},
        "rejected": {k: sorted(v) for k, v in sorted(rejected.items())},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")