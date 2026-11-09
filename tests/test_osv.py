import json
from unittest.mock import patch

import pytest

from huffman_cyber.feeds.osv import MAX_RESPONSE_BYTES, query_osv


class FakeResponse:
    status = 200

    def __init__(self, payload):
        self.payload = payload
        self.read_limit = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return "https://api.osv.dev/v1/querybatch"

    def read(self, limit):
        self.read_limit = limit
        return self.payload


def _sbom(components):
    return {"format": "CycloneDX", "components": components}


def test_query_uses_versionless_purl_and_version_field():
    response = FakeResponse(json.dumps({"results": [{"vulns": [
        {"id": "GHSA-abcd-1234", "modified": "2026-01-01T00:00:00Z"}
    ]}]}).encode())
    with patch("urllib.request.urlopen", return_value=response) as urlopen:
        result = query_osv(_sbom([
            {"name": "demo", "version": "1.2.3", "purl": "pkg:pypi/demo"}
        ]))
    request = urlopen.call_args.args[0]
    sent = json.loads(request.data)
    assert sent["queries"] == [
        {"package": {"purl": "pkg:pypi/demo"}, "version": "1.2.3"}
    ]
    assert result["finding_count"] == 1
    assert result["findings"][0]["match_type"] == "osv_package_version_query"
    assert result["findings"][0]["exploitation_status"] == "not_determined_by_osv_querybatch"
    assert len(result["request_sha256"]) == 1
    assert len(result["response_sha256"]) == 1


def test_versioned_purl_does_not_send_duplicate_version():
    response = FakeResponse(b'{"results":[{"vulns":[]}]}')
    with patch("urllib.request.urlopen", return_value=response) as urlopen:
        query_osv(_sbom([
            {"name": "demo", "version": "1.2.3", "purl": "pkg:pypi/demo@1.2.3"}
        ]))
    sent = json.loads(urlopen.call_args.args[0].data)
    assert sent["queries"] == [{"package": {"purl": "pkg:pypi/demo@1.2.3"}}]


def test_missing_purl_is_reported_without_network_call():
    with patch("urllib.request.urlopen") as urlopen:
        result = query_osv(_sbom([{"name": "unknown", "version": "1.0", "purl": ""}]))
    urlopen.assert_not_called()
    assert result["skipped_components"][0]["reason"] == "missing_or_invalid_package_url_or_version"


def test_duplicate_package_queries_are_deduplicated_and_fanned_out():
    response = FakeResponse(b'{"results":[{"vulns":[{"id":"CVE-2026-1234"}]}]}')
    components = [
        {"name": "first", "version": "1.0", "purl": "pkg:pypi/demo"},
        {"name": "second", "version": "1.0", "purl": "pkg:pypi/demo"},
    ]
    with patch("urllib.request.urlopen", return_value=response) as urlopen:
        result = query_osv(_sbom(components))
    sent = json.loads(urlopen.call_args.args[0].data)
    assert len(sent["queries"]) == 1
    assert result["finding_count"] == 2
    assert {item["component"] for item in result["findings"]} == {"first", "second"}


def test_query_batch_pagination_is_followed():
    first = FakeResponse(b'{"results":[{"vulns":[{"id":"CVE-2026-1234"}],"next_page_token":"next"}]}')
    second = FakeResponse(b'{"results":[{"vulns":[{"id":"GHSA-abcd-1234"}]}]}')
    with patch("urllib.request.urlopen", side_effect=[first, second]) as urlopen:
        result = query_osv(_sbom([
            {"name": "demo", "version": "1", "purl": "pkg:pypi/demo"}
        ]))
    assert urlopen.call_count == 2
    second_query = json.loads(urlopen.call_args_list[1].args[0].data)["queries"][0]
    assert second_query["page_token"] == "next"
    assert result["finding_count"] == 2
    assert result["complete"] is True


def test_malformed_response_fails_closed():
    response = FakeResponse(b'{"results":[{"vulns":"not-an-array"}]}')
    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(ValueError, match="vulns field"):
            query_osv(_sbom([
                {"name": "demo", "version": "1", "purl": "pkg:pypi/demo"}
            ]))


def test_oversized_response_is_rejected():
    response = FakeResponse(b"x" * (MAX_RESPONSE_BYTES + 1))
    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(ValueError, match="size limit"):
            query_osv(_sbom([
                {"name": "demo", "version": "1", "purl": "pkg:pypi/demo"}
            ]))


def test_unexpected_redirect_is_rejected():
    response = FakeResponse(b'{"results":[{"vulns":[]}]}')
    response.geturl = lambda: "https://attacker.invalid/collect"
    with patch("urllib.request.urlopen", return_value=response):
        with pytest.raises(ValueError, match="unexpected endpoint"):
            query_osv(_sbom([
                {"name": "demo", "version": "1", "purl": "pkg:pypi/demo"}
            ]))


def test_component_and_timeout_limits():
    with pytest.raises(ValueError, match="limited to"):
        query_osv(_sbom([{}] * 1001))
    with pytest.raises(ValueError, match="timeout"):
        query_osv(_sbom([]), timeout=0)
