"""IOC handling (DESIGN.md §6): all IOCs are defanged, only the defanged form
is stored, and a value that disagrees with its claimed kind is dropped rather
than stored un-defanged.

Every indicator here is synthetic: RFC 5737 documentation addresses, RFC 2606
reserved domains, and hashes made of repeated hex.
"""

from __future__ import annotations

import pytest

from enrich.defang import defang_ioc


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("url", "https://updates.watersync.example/payload.bin",
         "hxxps://updates[.]watersync[.]example/payload.bin"),
        ("url", "http://192.0.2.44/stage", "hxxp://192[.]0[.]2[.]44/stage"),
        ("domain", "updates.watersync.example", "updates[.]watersync[.]example"),
        ("ipv4", "192.0.2.44", "192[.]0[.]2[.]44"),
        ("ipv6", "2001:db8::1", "2001[:]db8[:][:]1"),
        ("email", "billing@watersync.example", "billing[@]watersync[.]example"),
    ],
)
def test_indicators_are_defanged(kind, value, expected):
    result = defang_ioc(kind, value)
    assert result.ok
    assert result.value_defanged == expected


def test_no_stored_value_is_clickable():
    """The §6 promise, stated directly: nothing that reaches storage retains a
    live scheme or an unescaped separator."""
    for kind, value in [
        ("url", "https://updates.watersync.example/x"),
        ("domain", "updates.watersync.example"),
        ("ipv4", "192.0.2.44"),
        ("email", "billing@watersync.example"),
    ]:
        stored = defang_ioc(kind, value).value_defanged
        assert "http://" not in stored and "https://" not in stored

        # After stripping bracketed separators, no bare separator may remain --
        # that is what makes the value inert.
        authority = stored.split("//", 1)[-1].split("/", 1)[0]
        bare = authority.replace("[.]", "").replace("[@]", "").replace("[:]", "")
        assert "." not in bare
        assert "@" not in bare
        assert ":" not in bare


def test_already_defanged_input_is_not_double_defanged():
    """Models often defang on their own initiative. The stored form has to be
    the same either way or the ioc unique constraint stops deduplicating."""
    fanged = defang_ioc("url", "https://updates.watersync.example/p")
    pre_defanged = defang_ioc("url", "hxxps://updates[.]watersync[.]example/p")
    assert pre_defanged.ok
    assert pre_defanged.value_defanged == fanged.value_defanged


def test_hashes_are_normalized_not_escaped():
    result = defang_ioc("sha256", "AA" * 32)
    assert result.ok
    assert result.value_defanged == "aa" * 32


# ---- kind/value disagreement is a defanging bypass ----


def test_url_mislabelled_as_a_hash_is_dropped():
    """The bypass this check exists for: trusting `kind` would store a live,
    clickable URL verbatim because hashes are not escaped."""
    result = defang_ioc("sha256", "https://updates.watersync.example/payload.bin")
    assert not result.ok
    assert result.value_defanged is None
    assert "claimed kind" in result.reason


def test_url_mislabelled_as_a_domain_is_dropped():
    result = defang_ioc("domain", "https://updates.watersync.example/payload.bin")
    assert not result.ok


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ipv4", "999.0.2.44"),
        ("ipv4", "not-an-ip"),
        ("sha256", "deadbeef"),
        ("md5", "AA" * 32 + "AA"),
        ("email", "no-at-sign.example"),
        ("domain", "not a domain at all"),
        ("url", "ftp://updates.watersync.example/x"),
    ],
)
def test_malformed_values_are_dropped(kind, value):
    assert not defang_ioc(kind, value).ok


def test_unknown_kind_is_dropped():
    result = defang_ioc("registry_key", r"HKLM\Software\Fake")
    assert not result.ok
    assert "unknown IOC kind" in result.reason
