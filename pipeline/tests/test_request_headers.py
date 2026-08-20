"""The request headers ingest/fetch.py sends (DESIGN.md §3).

Both were found empirically against the real feeds, and reverting either breaks
one source in a way no other test catches: CISA 403s any `Accept-Encoding`
containing `deflate` (httpx's default), and ACSC resets the connection for any
User-Agent carrying a "(+url)" suffix.
"""

from __future__ import annotations

import socket

from ingest.fetch import fetch_url
from tests.test_size_cap import _FakeResponse, _fake_getaddrinfo
import ingest.fetch as fetch_mod


class _CapturingClient:
    """Records the headers of the request it was asked to make."""

    captured: dict = {}

    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def stream(self, method, url, headers=None):
        _CapturingClient.captured = dict(headers or {})
        return self._response


def _capture(monkeypatch, **fetch_kwargs) -> dict:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo())
    response = _FakeResponse(chunks=[b"<rss/>"])
    monkeypatch.setattr(fetch_mod.httpx, "Client", lambda **kw: _CapturingClient(response))
    fetch_url("https://example.com/feed.xml", min_domain_delay=0, **fetch_kwargs)
    return _CapturingClient.captured


def test_advertises_gzip_only(monkeypatch):
    """`deflate` in this header is what CISA's bot management rejects."""
    assert _capture(monkeypatch)["Accept-Encoding"] == "gzip"


def test_user_agent_does_not_announce_a_url(monkeypatch):
    """A "(+https://...)" suffix is what ACSC's edge resets the connection on."""
    user_agent = _capture(monkeypatch)["User-Agent"]
    assert user_agent == "Pronoia-Ingest/0.1"
    assert "(+" not in user_agent


def test_conditional_headers_are_added_without_displacing_the_others(monkeypatch):
    headers = _capture(monkeypatch, etag='W/"abc"', last_modified="Wed, 21 Oct 2026 07:28:00 GMT")

    assert headers["If-None-Match"] == 'W/"abc"'
    assert headers["If-Modified-Since"] == "Wed, 21 Oct 2026 07:28:00 GMT"
    assert headers["Accept-Encoding"] == "gzip"
    assert headers["User-Agent"] == "Pronoia-Ingest/0.1"
