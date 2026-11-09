"""HTTPS transport helper that refuses redirects before following them."""
from __future__ import annotations

import urllib.error
import urllib.request


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_https_no_redirect(request: urllib.request.Request, *, timeout: float):
    """Open a fixed HTTPS request without forwarding it to redirect targets."""
    if not request.full_url.startswith("https://"):
        raise ValueError("only HTTPS requests are permitted")
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        return opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError("HTTP redirects are disabled for advisory feeds") from exc
        raise
