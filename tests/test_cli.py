import json
import sys

import pytest

from huffman_cyber.cli import main


def test_sbom_cli_inventory_and_kev_correlation(tmp_path, monkeypatch, capsys):
    sbom_path = tmp_path / "sample.cdx.json"
    kev_path = tmp_path / "kev-snapshot.json"
    inventory_path = tmp_path / "inventory.json"
    report_path = tmp_path / "sbom-kev-report.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "sample-package", "version": "1.2.3", "bom-ref": "pkg-1"}
                ],
                "vulnerabilities": [
                    {"id": "CVE-2025-1234", "affects": [{"ref": "pkg-1"}]}
                ],
            }
        ),
        encoding="utf-8",
    )
    kev_path.write_text(
        json.dumps(
            {
                "source": "synthetic-test-fixture",
                "sha256": "synthetic",
                "catalog": {"vulnerabilities": [{"cveID": "CVE-2025-1234"}]},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hco", "sbom", "inventory", str(sbom_path),
            "--output", str(inventory_path),
        ],
    )
    main()
    assert json.loads(inventory_path.read_text(encoding="utf-8"))["component_count"] == 1

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hco", "sbom", "correlate", str(sbom_path), str(kev_path),
            "--output", str(report_path),
        ],
    )
    main()
    result = json.loads(report_path.read_text(encoding="utf-8"))
    assert result["finding_count"] == 1
    assert "Found 1 explicit KEV match" in capsys.readouterr().out


def test_encrypt_cli_refuses_to_overwrite_destination(tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    destination = tmp_path / "encrypted.hco"
    source.write_text("sensitive payload", encoding="utf-8")
    destination.write_text("preserve existing data", encoding="utf-8")
    monkeypatch.setattr("huffman_cyber.cli.getpass.getpass", lambda _prompt: "strong unique passphrase")
    monkeypatch.setattr(
        sys,
        "argv",
        ["hco", "encrypt", str(source), str(destination)],
    )

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2
    assert destination.read_text(encoding="utf-8") == "preserve existing data"
