import csv
import json

from miner.dataset_builder import COLUMNS, REPO_COLUMNS, build_dataset


def _write_inputs(tmp_path):
    scan = {
        "organization": "acme",
        "repositories": [
            {"name": "web", "url": "https://github.com/acme/web", "status": "analyzed",
             "languages": ["Python"],
             "findings": [{"rule_id": "py/xss", "severity": "error", "message": "XSS",
                           "file": "a.py", "start_line": 3}],
             "sbom": {"components": 12}},
            {"name": "clean", "url": "https://github.com/acme/clean", "status": "analyzed",
             "languages": ["Python"], "findings": [], "sbom": {"components": 4}},
        ],
    }
    detail = {"matches": [{
        "vulnerability": {"id": "CVE-1", "severity": "High", "fix": {"versions": ["1.2"]}},
        "artifact": {"name": "lib", "version": "1.0", "locations": [{"path": "package.json"}]},
    }]}
    (tmp_path / "scan.json").write_text(json.dumps(scan))
    (tmp_path / "detail.json").write_text(json.dumps(detail))
    (tmp_path / "grype.json").write_text(json.dumps({"repositories": [
        {"full_name": "acme/web", "status": "success", "vulnerabilities": 1,
         "severity_counts": {"High": 1}, "report_path": str(tmp_path / "detail.json")},
        {"full_name": "acme/clean", "status": "no_vulnerabilities", "vulnerabilities": 0,
         "severity_counts": {}, "report_path": None},
    ]}))


def test_build_dataset_merges_codeql_and_grype(tmp_path):
    _write_inputs(tmp_path)
    rows = build_dataset(tmp_path / "scan.json", tmp_path / "grype.json", tmp_path / "out")

    assert {r["source"] for r in rows} == {"codeql", "grype"}
    assert all(set(r) == set(COLUMNS) for r in rows)
    assert (tmp_path / "out" / "dataset.csv").exists()


def test_repositories_csv_keeps_repos_without_findings(tmp_path):
    _write_inputs(tmp_path)
    build_dataset(tmp_path / "scan.json", tmp_path / "grype.json", tmp_path / "out")

    with open(tmp_path / "out" / "repositories.csv", encoding="utf-8") as fh:
        repos = {r["repository"]: r for r in csv.DictReader(fh)}

    assert set(repos["acme/web"]) == set(REPO_COLUMNS)
    assert repos["acme/web"]["grype_high"] == "1"
    assert repos["acme/clean"]["codeql_findings"] == "0"
    assert repos["acme/clean"]["grype_status"] == "no_vulnerabilities"
