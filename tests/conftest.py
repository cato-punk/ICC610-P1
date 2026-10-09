"""Fixtures compartidas para las pruebas del Reporter."""

from __future__ import annotations

from pathlib import Path

import pytest


def _write(base: Path, rel: str, content: str) -> None:
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """Repositorio de ejemplo con defectos sembrados para el inspector."""
    repo = tmp_path / "repo"

    _write(
        repo,
        ".github/workflows/ci.yml",
        """name: CI
on:
  push:
  pull_request_target:
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - name: persist
        uses: actions/checkout@v4
        with:
          persist-credentials: true
      - name: run
        run: echo "${{ github.event.pull_request.title }}"
""",
    )

    _write(
        repo,
        ".github/workflows/no-perms.yml",
        """name: No Perms
on:
  push:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
""",
    )

    _write(
        repo,
        "app.py",
        """import os
import subprocess

API_KEY = "sk-1234567890abcdef1234"


def run(cmd, user_input):
    subprocess.run(cmd, shell=True)
    os.system(cmd)
    return eval(user_input)
""",
    )

    _write(
        repo,
        "net.py",
        """import requests

requests.get("http://example.com", verify=False)
""",
    )

    _write(
        repo,
        "scripts/deploy.sh",
        """#!/usr/bin/env bash
chmod 777 /tmp/deploy
nsenter --target 1 --mount
""",
    )

    _write(repo, "Dockerfile", "FROM python:3.12-slim\nRUN echo hi\n")

    _write(repo, ".env", "TOKEN=abcdef1234567890\n")

    # Debe quedar excluido por el inspector.
    _write(
        repo,
        ".venv/lib/bad.py",
        "import subprocess\nsubprocess.run('x', shell=True)\n",
    )

    return repo
