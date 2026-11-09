"""HTTPS transport helper that refuses redirects before following them."""
from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlsplit


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_https_no_redirect(
    request: urllib.request.Request, *, timeout: float, allowed_host: str
):
    """Open a fixed HTTPS request without forwarding it to redirect targets."""
    parsed = urlsplit(request.full_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != allowed_host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("request URL does not match the permitted HTTPS host")
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        return opener.open(request, timeout=timeout)  # nosec B310: HTTPS host is allow-listed above
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError("HTTP redirects are disabled for advisory feeds") from exc
        raise
