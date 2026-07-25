"""IOC defanging (DESIGN.md §6: "All IOCs defanged at ingestion (hxxp, [.]);
the *fanged* form is never stored or displayed").

Two things happen here, and the second matters more than the first:

1. Defanging proper: hxxp/[.]/[:]/[@] substitution so a stored indicator can't
   be clicked, resolved, or pasted into a browser by accident.

2. Kind/value agreement. The `kind` field comes from the model, and defanging
   is kind-specific -- so a mislabelled IOC is a defanging bypass. A live URL
   emitted as kind='sha256' would be stored verbatim and fanged if we trusted
   the label. Every value is therefore validated against its claimed kind and
   dropped on mismatch, rather than being stored under a kind we can't defang.

The fanged form exists only inside `defang_ioc`, to normalize input the model
may have already defanged. It is never returned and never persisted.
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
        # Only the authority is dot-escaped; escaping dots in the path would
        # corrupt the indicator (a filename in the path is part of the IOC).
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
