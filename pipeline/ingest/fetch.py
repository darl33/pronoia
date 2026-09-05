"""Size-capped, SSRF-safe HTTP fetch: conditional GET, per-domain politeness
delay, and manual redirect handling with every hop re-validated (DESIGN.md §6).

Header choices: docs/DECISIONS.md#request-headers
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from ingest.ssrf import SSRFBlocked, pin_dns, resolve_and_validate, validate_url_scheme

DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # decompression-bomb ceiling, DESIGN.md §6
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_MIN_DOMAIN_DELAY_SECONDS = 2.0
DEFAULT_TIMEOUT_SECONDS = 15.0

# Bare identifier, no "(+url)" suffix. Both header values were found
# empirically and reverting either breaks one feed:
# docs/DECISIONS.md#request-headers
_USER_AGENT = "Pronoia-Ingest/0.1"

# Overrides httpx's default of "gzip, deflate"; CISA 403s any request
# advertising deflate.
_ACCEPT_ENCODING = "gzip"

_last_request_at: dict[str, float] = {}


class ResponseTooLarge(Exception):
    pass


class TooManyRedirects(Exception):
    pass


class HttpError(Exception):
    def __init__(self, status_code: int, url: str):
        super().__init__(f"{url} returned HTTP {status_code}")
        self.status_code = status_code
        self.url = url


@dataclass
class FetchResult:
    status_code: int
    final_url: str
    body: bytes
    etag: str | None
    last_modified: str | None


@dataclass
class NotModified:
    final_url: str


def _politeness_wait(hostname: str, min_delay: float) -> None:
    now = time.monotonic()
    last = _last_request_at.get(hostname)
    if last is not None:
        elapsed = now - last
        if elapsed < min_delay:
            time.sleep(min_delay - elapsed)
    _last_request_at[hostname] = time.monotonic()


def _do_one_request(
    url: str,
    *,
    etag: str | None,
    last_modified: str | None,
    max_bytes: int,
    min_domain_delay: float,
    timeout: float,
) -> tuple[str, object]:
    hostname, port = validate_url_scheme(url)
    validated = resolve_and_validate(hostname, port)

    headers = {"User-Agent": _USER_AGENT, "Accept-Encoding": _ACCEPT_ENCODING}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    _politeness_wait(hostname, min_domain_delay)

    with pin_dns(validated):
        with httpx.Client(follow_redirects=False, timeout=timeout) as client:
            with client.stream("GET", url, headers=headers) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if not location:
                        raise SSRFBlocked(f"redirect from {url} had no Location header")
                    return "redirect", urljoin(url, location)

                if response.status_code == 304:
                    return "not_modified", url

                if not (200 <= response.status_code < 300):
                    raise HttpError(response.status_code, url)

                content_length = response.headers.get("content-length")
                if content_length is not None and int(content_length) > max_bytes:
                    raise ResponseTooLarge(
                        f"{url} declared content-length {content_length} > {max_bytes} byte cap"
                    )

                chunks = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        response.close()
                        raise ResponseTooLarge(f"{url} exceeded {max_bytes} byte cap while streaming")
                    chunks.append(chunk)

                body = b"".join(chunks)
                return "ok", FetchResult(
                    status_code=response.status_code,
                    final_url=url,
                    body=body,
                    etag=response.headers.get("etag"),
                    last_modified=response.headers.get("last-modified"),
                )


def fetch_url(
    url: str,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    min_domain_delay: float = DEFAULT_MIN_DOMAIN_DELAY_SECONDS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> FetchResult | NotModified:
    """Fetch `url`, following up to `max_redirects` redirects. Every hop
    (including the first) is resolved and SSRF-validated independently, so a
    redirect can't be used to reach an address the initial check would have
    blocked."""
    current = url
    for _ in range(max_redirects + 1):
        kind, payload = _do_one_request(
            current,
            etag=etag,
            last_modified=last_modified,
            max_bytes=max_bytes,
            min_domain_delay=min_domain_delay,
            timeout=timeout,
        )
        if kind == "redirect":
            current = payload
            continue
        if kind == "not_modified":
            return NotModified(final_url=current)
        return payload

    raise TooManyRedirects(f"exceeded {max_redirects} redirects starting from {url}")
