"""IOC defanging (DESIGN.md §6): only the defanged form is ever stored.

`defang_ioc` validates one value against its claimed kind -- a mislabelled IOC
is a defanging bypass. `defang_text` scans free text and defangs everything it
finds, for gold-set fixtures.

Rationale: docs/DECISIONS.md#ioc-defang, docs/DECISIONS.md#defanging-fixtures
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,45}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_URL_RE = re.compile(r"^https?://[^\s]{3,2000}$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@" + _DOMAIN_RE.pattern[1:])


@dataclass(frozen=True)
class DefangResult:
    ok: bool
    value_defanged: str | None = None
    reason: str | None = None


def _refang_for_validation(value: str) -> str:
    """Undo common defanging so a value the model already defanged validates
    against its kind. Local to validation -- the result is never stored."""
    out = value.strip()
    for defanged, fanged in (
        ("[.]", "."), ("(.)", "."), ("[dot]", "."), (" dot ", "."),
        ("[:]", ":"), ("[@]", "@"), ("[at]", "@"),
        ("hxxps", "https"), ("hxxp", "http"),
    ):
        out = out.replace(defanged, fanged)
    return out


def _valid_ipv4(value: str) -> bool:
    match = _IPV4_RE.match(value)
    return bool(match) and all(0 <= int(octet) <= 255 for octet in match.groups())


_VALIDATORS = {
    "ipv4": _valid_ipv4,
    "ipv6": lambda v: bool(_IPV6_RE.match(v)) and v.count(":") >= 2,
    "domain": lambda v: bool(_DOMAIN_RE.match(v)),
    "url": lambda v: bool(_URL_RE.match(v)),
    "sha256": lambda v: bool(_SHA256_RE.match(v)),
    "md5": lambda v: bool(_MD5_RE.match(v)),
    "email": lambda v: bool(_EMAIL_RE.match(v)),
}


def _defang(kind: str, value: str) -> str:
    if kind == "url":
        scheme, _, rest = value.partition("://")
        neutered_scheme = "hxxps" if scheme.lower() == "https" else "hxxp"
        # Authority only -- escaping path dots would corrupt the indicator.
        authority, slash, path = rest.partition("/")
        return f"{neutered_scheme}://{authority.replace('.', '[.]')}{slash}{path}"
    if kind in ("ipv4", "domain"):
        return value.replace(".", "[.]")
    if kind == "ipv6":
        return value.replace(":", "[:]")
    if kind == "email":
        local, _, domain = value.rpartition("@")
        return f"{local}[@]{domain.replace('.', '[.]')}"
    # Hashes are not resolvable or clickable; lowercased for dedup only.
    return value.lower()


def defang_ioc(kind: str, value: str) -> DefangResult:
    """Validate `value` against its claimed `kind`, then return the defanged
    form. A mismatch is a drop, not a pass-through."""
    validator = _VALIDATORS.get(kind)
    if validator is None:
        return DefangResult(False, reason=f"unknown IOC kind {kind!r}")

    candidate = _refang_for_validation(value)
    if not validator(candidate):
        return DefangResult(False, reason=f"value does not match claimed kind {kind!r}")

    return DefangResult(True, value_defanged=_defang(kind, candidate))


# ---------- free-text scanning (gold-set fixtures) ----------

# Scanning counterparts to the anchored validators above. Order matters: URLs
# before domains, or the host inside a URL is defanged on its own and the
# scheme is left clickable.
_SCAN = (
    ("url", re.compile(r"\bhttps?://[^\s<>\"')\]]{3,2000}", re.IGNORECASE)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")),
    # Lookarounds, not \b: an SNMP OID (1.3.6.1.4.1.9.9.96.1.1) or a four-part
    # version contains dotted-decimal runs that \b happily matches inside.
    ("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("domain", re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|ru|cn|info|biz|top|xyz|online|site|club|shop|live|"
        r"icu|cc|tk|pw|su|me|co|uk|de|fr|nl|br|in|ir|kp|us|au|nz|ca|jp|kr)\b",
        re.IGNORECASE)),
)

# Left fanged: defanging these would corrupt the prose without making anything
# safer, and a reader needs them intact to annotate.
_SCAN_ALLOWLIST = frozenset({
    "cisa.gov", "www.cisa.gov", "cyber.gov.au", "www.cyber.gov.au",
    "mitre.org", "attack.mitre.org", "nvd.nist.gov", "nist.gov",
    "microsoft.com", "github.com", "talosintelligence.com",
    "blog.talosintelligence.com", "example.com", "example.org",
})


def _host_of(kind: str, value: str) -> str:
    """The hostname the allowlist should be checked against."""
    if kind == "url":
        return value.partition("://")[2].partition("/")[0].lower()
    if kind == "email":
        return value.rpartition("@")[2].lower()
    return value.lower().rstrip(".")


def defang_text(text: str) -> tuple[str, int]:
    """Defang every indicator in free text. Returns (text, count).

    For gold-set fixtures: real advisories carry live IOCs and CLAUDE.md forbids
    those anywhere in the repo. Over-defanging is the safe direction -- a
    mangled hostname costs an annotator nothing, a live one is the rule this
    exists to keep.
    """
    count = 0

    def replace(kind: str, match: re.Match) -> str:
        nonlocal count
        value = match.group(0)
        if _host_of(kind, value) in _SCAN_ALLOWLIST:
            return value
        result = defang_ioc(kind, value)
        if not result.ok or result.value_defanged == value:
            return value
        count += 1
        return result.value_defanged

    for kind, pattern in _SCAN:
        text = pattern.sub(lambda m, k=kind: replace(k, m), text)
    return text, count
