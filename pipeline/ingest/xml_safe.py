"""XXE-safe XML parsing for RSS/Atom feeds (DESIGN.md §6).

defusedxml blocks external entity expansion, internal entity expansion, and
DTD-based billion-laughs bombs by default. We additionally set forbid_dtd so
any DOCTYPE declaration at all is rejected outright, rather than trying to
distinguish a "safe" DOCTYPE from a malicious one.
"""

from __future__ import annotations

from xml.etree.ElementTree import Element

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring


class UnsafeXmlRejected(Exception):
    pass


def parse_xml(body: bytes) -> Element:
    try:
        return fromstring(body, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as exc:
        raise UnsafeXmlRejected(f"rejected XML: {exc}") from exc
    except SyntaxError as exc:
        raise UnsafeXmlRejected(f"malformed XML: {exc}") from exc
