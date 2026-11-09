import json
from unittest.mock import patch

import pytest

from huffman_cyber.feeds.kev import fetch_kev


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def read(self, limit):
        return json.dumps({
            "dateReleased": "2026-01-01",
            "count": 1,
            "vulnerabilities": [{
                "cveID": "CVE-2026-0001",
                "dateAdded": "2026-01-01",
                "vendorProject": "Example",
                "product": "Example Product",
                "vulnerabilityName": "Example vulnerability",
                "shortDescription": "Test record",
                "requiredAction": "Apply mitigations",
                "dueDate": "2026-02-01",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
            }],
        }).encode()


def test_feed_validation_and_provenance():
    with patch("huffman_cyber.feeds.kev.open_https_no_redirect", return_value=FakeResponse()):
        result = fetch_kev()
    assert result["vulnerability_count"] == 1
    assert result["source_url"].startswith("https://www.cisa.gov/")
    assert len(result["sha256"]) == 64


def test_feed_rejects_invalid_cve_id():
    response = FakeResponse()
    response.read = lambda limit: json.dumps({
        "dateReleased": "2026-01-01",
        "vulnerabilities": [{"cveID": "CVE-not-valid", "dateAdded": "2026-01-01"}],
    }).encode()
    with patch("huffman_cyber.feeds.kev.open_https_no_redirect", return_value=response):
        with pytest.raises(ValueError, match="invalid CVE ID"):
            fetch_kev()


def test_feed_rejects_count_mismatch():
    response = FakeResponse()
    response.read = lambda limit: json.dumps({
        "dateReleased": "2026-01-01",
        "count": 2,
        "vulnerabilities": [],
    }).encode()
    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(ValueError, match="count does not match"):
            fetch_kev()


def test_feed_rejects_redirect_outside_cisa():
    response = FakeResponse()
    response.geturl = lambda: "https://attacker.invalid/kev.json"
    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(ValueError, match="unexpected endpoint"):
            fetch_kev()
