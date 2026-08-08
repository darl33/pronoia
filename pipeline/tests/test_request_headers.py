"""The request headers ingest/fetch.py sends.

Both are load-bearing and both were found empirically against the real feeds in
DESIGN.md §3, so they are pinned here: silently reverting either one breaks
ingestion from a specific source in a way no other test would catch.

* `Accept-Encoding: gzip` — httpx defaults to "gzip, deflate", and CISA's edge
  403s any request that advertises `deflate`. Isolated header by header: the
  same User-Agent gets 403 with "gzip, deflate" and 200 with "gzip".
* `User-Agent` without a "(+url)" suffix — ACSC's edge resets the connection
  for any bot-announcing UA.
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
