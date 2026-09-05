"""Turn a fetched feed body into zero or more ParsedDocument records, one per
raw_document row. Supports the four feed.kind values from DESIGN.md §3/§4:
rss, atom, html, json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from xml.etree.ElementTree import Element

from ingest.sanitize import html_to_clean_text
from ingest.xml_safe import parse_xml

ATOM_NS = "{http://www.w3.org/2005/Atom}"
CONTENT_ENCODED = "{http://purl.org/rss/1.0/modules/content/}encoded"


@dataclass
class ParsedDocument:
    source_url: str
    title: str | None
    published_at: datetime | None
    raw_html: str
    clean_text: str


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _text(el: Element | None) -> str | None:
    if el is None or el.text is None:
        return None
    return el.text.strip() or None


def parse_rss(body: bytes) -> list[ParsedDocument]:
    root = parse_xml(body)
    channel = root.find("channel")
    if channel is None:
        return []

    docs = []
    for item in channel.findall("item"):
        link = _text(item.find("link"))
        if not link:
            continue
        content = _text(item.find(CONTENT_ENCODED)) or _text(item.find("description")) or ""
        docs.append(
            ParsedDocument(
                source_url=link,
                title=_text(item.find("title")),
                published_at=_parse_date(_text(item.find("pubDate"))),
                raw_html=content,
                clean_text=html_to_clean_text(content),
            )
        )
    return docs


def parse_atom(body: bytes) -> list[ParsedDocument]:
    root = parse_xml(body)
    docs = []
    for entry in root.findall(f"{ATOM_NS}entry"):
        link_el = entry.find(f"{ATOM_NS}link")
        link = link_el.get("href") if link_el is not None else None
        if not link:
            continue
        content = (
            _text(entry.find(f"{ATOM_NS}content"))
            or _text(entry.find(f"{ATOM_NS}summary"))
            or ""
        )
        published = _text(entry.find(f"{ATOM_NS}published")) or _text(entry.find(f"{ATOM_NS}updated"))
        docs.append(
            ParsedDocument(
                source_url=link,
                title=_text(entry.find(f"{ATOM_NS}title")),
                published_at=_parse_date(published),
                raw_html=content,
                clean_text=html_to_clean_text(content),
            )
        )
    return docs


def parse_html_page(body: bytes, source_url: str) -> list[ParsedDocument]:
    from bs4 import BeautifulSoup

    html = body.decode("utf-8", errors="replace")
    soup = BeautifulSoup(html, "html.parser")
    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else None
    return [
        ParsedDocument(
            source_url=source_url,
            title=title,
            published_at=None,
            raw_html=html,
            clean_text=html_to_clean_text(html),
        )
    ]


def parse_json_snapshot(body: bytes, source_url: str, feed_name: str) -> list[ParsedDocument]:
    """Generic 'json' feed kind: one raw_document per poll representing the
    current snapshot of the resource (e.g. the MISP galaxy cluster file).
    Reference-data import into typed tables (threat_actor, attack_technique)
    is a separate, later step -- this just lands the raw snapshot."""
    raw_text = body.decode("utf-8", errors="replace")
    data = json.loads(raw_text)

    summary_lines = [feed_name]
    if isinstance(data, dict):
        description = data.get("description")
        if description:
            summary_lines.append(str(description))
        values = data.get("values")
        if isinstance(values, list):
            summary_lines.append(f"{len(values)} entries:")
            for entry in values:
                if isinstance(entry, dict) and "value" in entry:
                    summary_lines.append(f"- {entry['value']}")
    clean_text = "\n".join(summary_lines) if len(summary_lines) > 1 else raw_text

    return [
        ParsedDocument(
            source_url=source_url,
            title=feed_name,
            published_at=None,
            raw_html=raw_text,
            clean_text=clean_text,
        )
    ]


def parse_feed_body(kind: str, body: bytes, source_url: str, feed_name: str) -> list[ParsedDocument]:
    if kind == "rss":
        return parse_rss(body)
    if kind == "atom":
        return parse_atom(body)
    if kind == "html":
        return parse_html_page(body, source_url)
    if kind == "json":
        return parse_json_snapshot(body, source_url, feed_name)
    raise ValueError(f"unknown feed kind {kind!r}")
