"""Synthetic Cyber Observatory SBOM report to OIX evidence demonstration."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from oix.identity import generate_identity
from oix.inbox import SQLiteInbox
from oix.policy import CapabilityPolicy

from huffman_cyber.oix_bridge import create_evidence_message


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="hco-oix-") as directory:
        root = Path(directory)
        sender = generate_identity(
            root / "sender", "Cyber Observatory Demo", ["public.research"]
        )
        receiver = generate_identity(
            root / "receiver", "OIX Demo Receiver", ["public.research"]
        )
        report = root / "synthetic-sbom-report.json"
        report.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "sbom_format": "CycloneDX",
                    "component_count": 12,
                    "finding_count": 1,
                    "findings": [
                        {
                            "cve_id": "CVE-2026-12345",
                            "match_type": "explicit_sbom_cve_reference",
                            "requires_manual_triage": True,
                        }
                    ],
                    "synthetic": True,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        envelope = create_evidence_message(
            identity_dir=root / "sender",
            recipient=receiver["card"]["agent_id"],
            artifact_path=report,
            evidence_type="sbom_analysis",
            method_name="synthetic-sbom-kev-correlation",
            method_version="1.0",
            summary={"component_count": 12, "finding_count": 1, "synthetic": True},
            limitations=[
                "Synthetic example; an SBOM match does not prove exploitability."
            ],
            classification="internal",
            status="derived",
        )
        inbox = SQLiteInbox(
            root / "receiver.sqlite3",
            receiver["card"]["agent_id"],
            CapabilityPolicy({"public.research"}),
        )
        inbox.trust_peer(sender)
        receipt = inbox.receive(envelope)
        print(
            json.dumps(
                {
                    "message_type": receipt.message_type,
                    "work_status": receipt.work_status,
                    "evidence_type": envelope["body"]["payload"]["evidence_type"],
                    "artifact_sha256": envelope["body"]["payload"]["artifact"]["sha256"],
                    "artifact_uploaded": False,
                    "operator_review_required": True,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
