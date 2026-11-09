import json

import pytest

from huffman_cyber.sbom import MAX_SBOM_BYTES, correlate_kev, load_sbom


def test_load_cyclonedx_inventory(tmp_path):
    source = tmp_path / "bom.json"
    source.write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "components": [{"bom-ref": "demo-ref", "name": "demo", "version": "1.2", "purl": "pkg:pypi/demo@1.2"}],
        "vulnerabilities": [{"id": "CVE-2026-1234", "affects": [{"ref": "demo-ref"}]}]
    }))
    result = load_sbom(source)
    assert result["format"] == "CycloneDX"
    assert result["components"][0]["purl"] == "pkg:pypi/demo@1.2"
    assert result["components"][0]["cve_ids"] == ["CVE-2026-1234"]


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


def test_oversized_sbom_is_rejected(tmp_path):
    source = tmp_path / "oversized.json"
    source.write_bytes(b" " * (MAX_SBOM_BYTES + 1))
    with pytest.raises(ValueError, match="size limit"):
        load_sbom(source)


def test_malformed_component_is_not_silently_skipped(tmp_path):
    source = tmp_path / "malformed.json"
    source.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [None]}))
    with pytest.raises(ValueError, match="must be an object"):
        load_sbom(source)


def test_non_string_package_fields_are_rejected(tmp_path):
    source = tmp_path / "malformed.json"
    source.write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "components": [{"name": {"unexpected": "object"}, "version": "1"}],
    }))
    with pytest.raises(ValueError, match="must be a string"):
        load_sbom(source)


def test_duplicate_bom_refs_are_rejected(tmp_path):
    source = tmp_path / "duplicate.json"
    source.write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "same", "name": "first"},
            {"bom-ref": "same", "name": "second"},
        ],
    }))
    with pytest.raises(ValueError, match="duplicate"):
        load_sbom(source)
