"""Grype CLI interaction module for SBOM vulnerability scanning."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible")


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    # Grype's JSON embeds package metadata that is frequently non-ASCII, so the
    # platform default codec (cp1252 on Windows) is not enough: decoding raises
    # UnicodeDecodeError inside the reader thread and leaves stdout as None.
    # `errors="replace"` keeps one bad byte from aborting the whole scan.
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"stderr: {result.stderr}\n"
            f"stdout: {result.stdout}"
        )
    return result


def get_grype_version() -> str:
    """Return the installed Grype version string (e.g. '0.120.0')."""
    result = _run(["grype", "version"])
    match = re.search(r"(?im)^\s*Version:\s*(\S+)", result.stdout)
    if match:
        return match.group(1)

    # Fallback: some builds only expose version info through JSON output.
    # Grype uses `-o json` here; `--format json` is Syft syntax and fails.
    try:
        result = _run(["grype", "version", "-o", "json"])
        version = json.loads(result.stdout).get("version", "")
        if version:
            return str(version)
    except Exception:
        pass

    first_line = next(
        (line.strip() for line in result.stdout.splitlines() if line.strip()),
        "",
    )
    return first_line


def scan_sbom(sbom_path: Path, output_path: Path) -> Path:
    """Scan a CycloneDX SBOM with Grype and write JSON results."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    result = _run([
        "grype",
        f"sbom:{sbom_path}",
        "-o",
        "json",
    ])

    output_path.write_text(
        result.stdout,
        encoding="utf-8",
    )

    return output_path


def _load_report(report_path: Path) -> dict:
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


def count_vulnerabilities(report_path: Path) -> int:
    """Return the number of vulnerability matches in a Grype report.

    Counts matches, which is one entry per vulnerable package instance rather
    than one per distinct CVE: a library required by three packages counts
    three times.
    """
    return len(_load_report(report_path).get("matches", []))


def severity_counts(report_path: Path) -> dict[str, int]:
    """Return vulnerability match counts keyed by severity.

    Every severity in ``SEVERITIES`` is always present so callers can render a
    stable set of columns. An unrecognised severity, if Grype ever introduces
    one, is added as an extra key rather than being dropped.
    """
    counts = {severity: 0 for severity in SEVERITIES}
    for match in _load_report(report_path).get("matches", []):
        severity = (match.get("vulnerability") or {}).get("severity", "")
        counts[severity] = counts.get(severity, 0) + 1
    return counts