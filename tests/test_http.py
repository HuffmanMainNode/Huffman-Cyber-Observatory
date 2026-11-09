import urllib.error
import urllib.request
from unittest.mock import Mock, patch

import pytest

from huffman_cyber.feeds.http import open_https_no_redirect


def test_redirect_is_rejected_without_following_target():
    request = urllib.request.Request("https://example.invalid/feed")
    opener = Mock()
    opener.open.side_effect = urllib.error.HTTPError(
        request.full_url, 302, "Found", {}, None
    )
    with patch("urllib.request.build_opener", return_value=opener):
        with pytest.raises(ValueError, match="redirects are disabled"):
            open_https_no_redirect(request, timeout=5, allowed_host="example.invalid")
    opener.open.assert_called_once_with(request, timeout=5)


def test_non_https_request_is_rejected_before_opening():
    request = __import__("urllib.request").request.Request("http://example.invalid/feed")
    with patch("urllib.request.build_opener") as build_opener:
        with pytest.raises(ValueError, match="permitted HTTPS host"):
            open_https_no_redirect(request, timeout=5)
    build_opener.assert_not_called()
