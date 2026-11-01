import json

from huffman_cyber.sbom import correlate_kev, load_sbom


def test_load_cyclonedx_inventory(tmp_path):
    source = tmp_path / "bom.json"
    source.write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "components": [{"name": "demo", "version": "1.2", "purl": "pkg:pypi/demo@1.2"}]
    }))
    result = load_sbom(source)
    assert result["format"] == "CycloneDX"
    assert result["components"][0]["purl"] == "pkg:pypi/demo@1.2"


def test_load_spdx_inventory(tmp_path):
    source = tmp_path / "bom.json"
    source.write_text(json.dumps({
        "spdxVersion": "SPDX-2.3",
        "packages": [{"name": "demo", "versionInfo": "1.2", "externalRefs": [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceLocator": "pkg:pypi/demo@1.2"}
        ]}]
    }))
    result = load_sbom(source)
    assert result["format"] == "SPDX"
    assert result["components"][0]["name"] == "demo"


def test_kev_correlation_only_matches_explicit_cves():
    sbom = {"format": "CycloneDX", "component_count": 1, "components": [
        {"name": "demo", "version": "1", "cve_ids": ["CVE-2026-1234"]}
    ]}
    kev = {"source": "test", "sha256": "a" * 64, "catalog": {
        "vulnerabilities": [{"cveID": "CVE-2026-1234"}]
    }}
    result = correlate_kev(sbom, kev)
    assert result["finding_count"] == 1
    assert result["findings"][0]["requires_manual_triage"] is True
