"""Punto de entrada del Reporter: `python -m reporter.cli`."""

from pathlib import Path

from . import llm_client, markdown_generator, repo_inspector


def main() -> None:
    evidence = repo_inspector.collect_evidence(Path.cwd())
    report = llm_client.analyze(evidence)
    path = markdown_generator.write_report(report)
    print(f"Report written to {path}")


if __name__ == "__main__":
    main()
