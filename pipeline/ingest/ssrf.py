"""SSRF mitigation: DNS resolution, private/link-local/metadata range rejection,
and DNS pinning so the validated address is the one connected to (DESIGN.md §6).

Why pinning, not just validation: docs/DECISIONS.md#ssrf
"""

from __future__ import annotations

import ipaddress
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"https"}


class SSRFBlocked(Exception):
    pass


def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


@dataclass(frozen=True)
class ValidatedHost:
    hostname: str
    port: int
    ip: str
    family: int


def validate_url_scheme(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise SSRFBlocked(f"scheme {parts.scheme!r} not allowed, only {ALLOWED_SCHEMES}")
    if not parts.hostname:
        raise SSRFBlocked(f"no hostname in url {url!r}")
    return parts.hostname, parts.port or 443


def resolve_and_validate(hostname: str, port: int) -> ValidatedHost:
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"DNS resolution failed for {hostname}: {exc}") from exc

    if not infos:
        raise SSRFBlocked(f"DNS resolution returned no addresses for {hostname}")

    validated = []
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if _is_disallowed_ip(ip):
            raise SSRFBlocked(f"{hostname} resolved to disallowed address {ip}")
        validated.append((family, sockaddr[0]))

    family, ip = validated[0]
    return ValidatedHost(hostname=hostname, port=port, ip=ip, family=family)


@contextmanager
def pin_dns(validated: ValidatedHost):
    """Force socket.getaddrinfo to answer `validated.hostname` with the single
    address that was already checked by resolve_and_validate, for the
    duration of the request. Other hostnames resolve normally."""
    real_getaddrinfo = socket.getaddrinfo
    pinned_sockaddr = (validated.ip, validated.port)

    def patched(host, port, family=0, type=0, proto=0, flags=0):
        if host == validated.hostname and port == validated.port:
            return [(validated.family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", pinned_sockaddr)]
        return real_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = patched
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo
