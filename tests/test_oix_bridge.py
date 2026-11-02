from __future__ import annotations

import hashlib

import pytest

pytest.importorskip("oix")

from oix.identity import generate_identity
from oix.inbox import InboxError, SQLiteInbox
from oix.policy import CapabilityPolicy

from huffman_cyber.oix_bridge import create_evidence_message


def test_sbom_report_becomes_signed_metadata_only_evidence(tmp_path):
    sender_dir, receiver_dir = tmp_path / "sender", tmp_path / "receiver"
    sender_card = generate_identity(sender_dir, "Cyber Observatory", ["public.research"])
    receiver_card = generate_identity(receiver_dir, "OIX Receiver", ["public.research"])
    report = tmp_path / "sbom-kev-report.json"
    content = (
        b'{"schema_version":"1.0","sbom_format":"CycloneDX",'
        b'"component_count":12,"finding_count":1,"findings":[{"cve_id":"CVE-2026-12345"}]}'
    )
    report.write_bytes(content)

    message = create_evidence_message(
        identity_dir=sender_dir,
        recipient=receiver_card["card"]["agent_id"],
        artifact_path=report,
        evidence_type="sbom_analysis",
        method_name="explicit-sbom-cve-to-kev-correlation",
        method_version="1.0",
        summary={
            "component_count": 12,
            "finding_count": 1,
            "match_type": "explicit_sbom_cve_reference",
        },
        limitations=[
            "An SBOM match does not prove the vulnerable code path is present or reachable."
        ],
        classification="internal",
        status="derived",
    )

    payload = message["body"]["payload"]
    assert payload["artifact"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert payload["artifact"]["size_bytes"] == len(content)
    assert payload["evidence_type"] == "sbom_analysis"
    assert content.decode() not in str(payload)

    inbox = SQLiteInbox(
        tmp_path / "receiver.sqlite3",
        receiver_card["card"]["agent_id"],
        CapabilityPolicy({"public.research"}),
    )
    inbox.trust_peer(sender_card)
    receipt = inbox.receive(message)
    assert receipt.message_type == "evidence.submit"
    assert receipt.work_status == "pending_review"
    assert inbox.pending_work()[0]["payload"] == payload


def test_cyber_bridge_rejects_non_sbom_evidence_types(tmp_path):
    identity_dir = tmp_path / "identity"
    generate_identity(identity_dir, "Cyber Observatory", ["public.research"])
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="sbom_analysis or file_manifest"):
        create_evidence_message(
            identity_dir=identity_dir,
            recipient="ed25519:" + "a" * 64,
            artifact_path=report,
            evidence_type="domain_observation",
            method_name="unsupported",
            method_version="1.0",
            summary={"finding_count": 0},
            limitations=["Not a domain observation."],
        )


def test_cyber_bridge_rejects_non_deterministic_summary(tmp_path):
    identity_dir = tmp_path / "identity"
    generate_identity(identity_dir, "Cyber Observatory", ["public.research"])
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(InboxError):
        create_evidence_message(
            identity_dir=identity_dir,
            recipient="ed25519:" + "a" * 64,
            artifact_path=report,
            evidence_type="sbom_analysis",
            method_name="sbom-correlation",
            method_version="1.0",
            summary={"confidence": 0.95},
            limitations=["Confidence is not computed."],
        )
