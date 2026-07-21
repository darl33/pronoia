"""Tests for the response size cap in ingest/fetch.py (DESIGN.md §6:
decompression bombs / oversized responses)."""

from __future__ import annotations

import socket

import pytest

import ingest.fetch as fetch_mod
from ingest.fetch import DEFAULT_MAX_BYTES, ResponseTooLarge, fetch_url


def _fake_getaddrinfo(ip="93.184.216.34"):
    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    return fake


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, chunks=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = chunks or []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_bytes(self):
        yield from self._chunks

    def close(self):
        pass


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def stream(self, method, url, headers=None):
        return self._response


def _patch_client(monkeypatch, response):
    monkeypatch.setattr(fetch_mod.httpx, "Client", lambda **kw: _FakeClient(response))


def test_rejects_via_content_length_header(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo())
    response = _FakeResponse(headers={"content-length": str(DEFAULT_MAX_BYTES + 1)})
    _patch_client(monkeypatch, response)

    with pytest.raises(ResponseTooLarge):
        fetch_url("https://example.com/feed.xml", min_domain_delay=0)


def test_rejects_when_streamed_body_exceeds_cap_despite_no_content_length(monkeypatch):
    """A response that lies about (or omits) Content-Length -- e.g. a
    decompression bomb -- must still be caught while streaming."""
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo())
    chunks = [b"x" * 1024] * 20  # 20 KiB total, no content-length header at all
    response = _FakeResponse(headers={}, chunks=chunks)
    _patch_client(monkeypatch, response)

    with pytest.raises(ResponseTooLarge):
        fetch_url("https://example.com/feed.xml", max_bytes=10 * 1024, min_domain_delay=0)


def test_accepts_body_within_cap(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo())
    chunks = [b"hello ", b"world"]
    response = _FakeResponse(headers={"etag": '"abc"'}, chunks=chunks)
    _patch_client(monkeypatch, response)

    result = fetch_url("https://example.com/feed.xml", max_bytes=1024, min_domain_delay=0)

    assert result.body == b"hello world"
    assert result.etag == '"abc"'
