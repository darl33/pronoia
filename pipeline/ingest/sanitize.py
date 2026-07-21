"""raw_html -> clean_text extraction (DESIGN.md §6).

raw_html is stored exactly as fetched and is never rendered. clean_text is a
text-only extraction for everything downstream (enrichment prompts, frontend
display) so stored/rendered HTML/script content can't reach a browser.
Uses the stdlib 'html.parser' backend (pure Python, no DTD/entity handling of
its own) rather than an lxml-backed parser, so this step carries no XXE
surface independent of xml_safe.py.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

_WHITESPACE_RE = re.compile(r"[ \t\r\f\v]+")
_BLANK_LINES_RE = re.compile(r"\n{3,}")


def html_to_clean_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = soup.get_text(separator="\n")
    text = _WHITESPACE_RE.sub(" ", text)
    text = "\n".join(line.strip() for line in text.splitlines())
    text = _BLANK_LINES_RE.sub("\n\n", text)
    return text.strip()


def normalize_whitespace(text: str) -> str:
    """Used to compare text for dedup/evidence-quote matching independent of
    incidental whitespace differences."""
    return re.sub(r"\s+", " ", text).strip()
