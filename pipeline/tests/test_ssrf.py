"""Tests for ingest/ssrf.py (DESIGN.md §6: SSRF via feed URLs / redirects)."""

from __future__ import annotations

import socket

import pytest

from ingest.ssrf import SSRFBlocked, pin_dns, resolve_and_validate, validate_url_scheme

PUBLIC_IP = "93.184.216.34"  # example.com-style public address


def _fake_getaddrinfo(ip: str, family=socket.AF_INET):
    def fake(host, port, *args, **kwargs):
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    return fake


@pytest.mark.parametrize(
    "bad_ip",
    [
        "127.0.0.1",       # loopback
        "10.1.2.3",        # RFC1918 private
        "172.16.0.5",      # RFC1918 private
        "192.168.1.1",     # RFC1918 private
        "169.254.169.254", # link-local / cloud metadata
        "0.0.0.0",         # unspecified
        "224.0.0.1",       # multicast
    ],
)
def test_rejects_disallowed_ipv4(monkeypatch, bad_ip):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(bad_ip))
    with pytest.raises(SSRFBlocked):
        resolve_and_validate("looks-external.example.com", 443)


@pytest.mark.parametrize(
    "bad_ip",
    [
        "::1",              # loopback
        "fe80::1",          # link-local
        "fc00::1",          # unique local (private)
        "::ffff:127.0.0.1", # IPv4-mapped loopback
    ],
)
def test_rejects_disallowed_ipv6(monkeypatch, bad_ip):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(bad_ip, family=socket.AF_INET6))
    with pytest.raises(SSRFBlocked):
        resolve_and_validate("looks-external.example.com", 443)


def test_allows_public_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(PUBLIC_IP))
    validated = resolve_and_validate("cisa.gov", 443)
    assert validated.ip == PUBLIC_IP


def test_dns_rebinding_is_blocked_by_pinning(monkeypatch):
    """The classic rebinding attack: the hostname resolves to a public IP at
    validation time, but the attacker's DNS server would answer with a
    private IP on a second lookup made right before the real connect. A
    naive "validate hostname, then let the HTTP client resolve it again"
    implementation is vulnerable; pin_dns must make the second lookup return
    the already-validated address instead of hitting the resolver again."""
    hostname, port = "attacker-controlled.example.com", 443

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(PUBLIC_IP))
    validated = resolve_and_validate(hostname, port)
    assert validated.ip == PUBLIC_IP

    # Attacker's DNS now answers with a private/internal address.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.0.0.1"))

    with pin_dns(validated):
        # This simulates the lookup the HTTP client's connect() would do.
        infos = socket.getaddrinfo(hostname, port)
        _, _, _, _, sockaddr = infos[0]
        assert sockaddr[0] == PUBLIC_IP  # pinned, not the rebound private IP

    # Outside the pin, resolution reverts: the patch is properly scoped.
    infos = socket.getaddrinfo(hostname, port)
    assert infos[0][4][0] == "10.0.0.1"


def test_pin_dns_does_not_affect_other_hosts(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(PUBLIC_IP))
    validated = resolve_and_validate("cisa.gov", 443)

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("198.51.100.7"))
    with pin_dns(validated):
        other = socket.getaddrinfo("blog.talosintelligence.com", 443)
        assert other[0][4][0] == "198.51.100.7"


@pytest.mark.parametrize("url", ["http://cisa.gov/feed.xml", "file:///etc/passwd", "ftp://cisa.gov/x"])
def test_rejects_non_https_scheme(url):
    with pytest.raises(SSRFBlocked):
        validate_url_scheme(url)


def test_accepts_https_scheme():
    hostname, port = validate_url_scheme("https://cisa.gov/feed.xml")
    assert hostname == "cisa.gov"
    assert port == 443
