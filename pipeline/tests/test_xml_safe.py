"""Tests for ingest/xml_safe.py (DESIGN.md §6: XXE / entity expansion in XML feeds)."""

from __future__ import annotations

import pytest

from ingest.xml_safe import UnsafeXmlRejected, parse_xml

XXE_EXTERNAL_ENTITY = b"""<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
"""

BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>
"""

BENIGN_DOCTYPE = b"""<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "harmless.dtd">
<root><item>fine</item></root>
"""

BENIGN_RSS = b"""<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Example Feed</title>
    <item>
      <title>Item One</title>
      <link>https://example.com/one</link>
      <description>hello</description>
      <pubDate>Wed, 02 Oct 2024 13:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""


def test_rejects_external_entity():
    with pytest.raises(UnsafeXmlRejected):
        parse_xml(XXE_EXTERNAL_ENTITY)


def test_rejects_billion_laughs():
    with pytest.raises(UnsafeXmlRejected):
        parse_xml(BILLION_LAUGHS)


def test_rejects_any_doctype_even_without_entities():
    with pytest.raises(UnsafeXmlRejected):
        parse_xml(BENIGN_DOCTYPE)


def test_rejects_malformed_xml():
    with pytest.raises(UnsafeXmlRejected):
        parse_xml(b"<root><unclosed></root>")


def test_parses_benign_rss():
    root = parse_xml(BENIGN_RSS)
    assert root.tag == "rss"
    item = root.find("channel").find("item")
    assert item.find("title").text == "Item One"
