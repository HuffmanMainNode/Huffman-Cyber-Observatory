import json
from unittest.mock import patch

from huffman_cyber.feeds.kev import fetch_kev


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return json.dumps({
            "dateReleased": "2026-01-01",
            "vulnerabilities": [{"cveID": "CVE-2026-0001"}],
        }).encode()


def test_feed_validation_and_provenance():
    with patch("urllib.request.urlopen", return_value=FakeResponse()):
        result = fetch_kev()
    assert result["vulnerability_count"] == 1
    assert result["source_url"].startswith("https://www.cisa.gov/")
    assert len(result["sha256"]) == 64