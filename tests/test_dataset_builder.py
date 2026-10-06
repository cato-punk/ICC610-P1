import json

from miner.dataset_builder import COLUMNS, build_dataset


def test_build_dataset_merges_codeql_and_grype(tmp_path):
    scan = {
        "organization": "acme",
        "repositories": [{
            "name": "web",
            "findings": [{"rule_id": "js/xss", "severity": "error",
                          "message": "XSS", "file": "a.js", "start_line": 3}],
        }],
    }
    grype_detail = {"matches": [{
        "vulnerability": {"id": "CVE-1", "severity": "High", "fix": {"versions": ["1.2"]}},
        "artifact": {"name": "lib", "version": "1.0", "locations": [{"path": "package.json"}]},
    }]}
    (tmp_path / "scan.json").write_text(json.dumps(scan))
    (tmp_path / "detail.json").write_text(json.dumps(grype_detail))
    (tmp_path / "grype.json").write_text(json.dumps({"repositories": [
        {"full_name": "acme/web", "report_path": str(tmp_path / "detail.json")}]}))

    rows = build_dataset(tmp_path / "scan.json", tmp_path / "grype.json", tmp_path / "out")

    assert {r["source"] for r in rows} == {"codeql", "grype"}
    assert all(set(r) == set(COLUMNS) for r in rows)
    assert (tmp_path / "out" / "dataset.csv").exists()
