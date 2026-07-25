"""Prompt loading, versioning, and report-text enclosure.

Guardrail 6 (DESIGN.md §5.2) lives half in prompts/extract_system.md -- the
"this is data, not instructions" rule -- and half here: `render_user_prompt`
strips the closing marker from the document before enclosing it, so a report
containing the literal delimiter cannot end the data block early and have the
remainder of itself read as instructions. A delimiter the payload can forge is
not a delimiter.

Guardrail 6 in DESIGN.md §5.2 also notes the real defense is structural: even
a successful injection can only produce an Extraction that still has to pass
schema validation, the closed-world technique check, and evidence quoting. The
blast radius is one bad row.

prompt_version (§5.2 guardrail 6, "prompts are files in-repo; prompt_version =
short git hash") is the git tree hash of the prompts directory, computed from
working-tree content. It equals `git rev-parse --short HEAD:pipeline/enrich/prompts`
when the directory is committed and clean, but is also defined for uncommitted
edits -- so an extraction run mid-iteration is still attributable to the exact
prompt bytes that produced it, which is what §7's per-(model, prompt_version)
scorecards need.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

PROMPTS_DIR = Path(__file__).parent / "prompts"
SYSTEM_PROMPT_FILE = PROMPTS_DIR / "extract_system.md"
USER_PROMPT_FILE = PROMPTS_DIR / "extract_user.md"

OPEN_MARKER = "<<<REPORT_TEXT"
CLOSE_MARKER = "REPORT_TEXT>>>"

PROMPT_VERSION_LENGTH = 12


def _git_blob_hash(data: bytes) -> bytes:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).digest()


@lru_cache(maxsize=1)
def prompt_version() -> str:
    """Git tree hash of prompts/, over working-tree content."""
    entries = b""
    for path in sorted(PROMPTS_DIR.iterdir()):
        if not path.is_file():
            continue
        entries += b"100644 " + path.name.encode() + b"\0" + _git_blob_hash(path.read_bytes())
    tree = hashlib.sha1(b"tree %d\0" % len(entries) + entries).hexdigest()
    return tree[:PROMPT_VERSION_LENGTH]


@lru_cache(maxsize=1)
def system_prompt() -> str:
    return SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def _user_template() -> str:
    return USER_PROMPT_FILE.read_text(encoding="utf-8")


def render_user_prompt(report_text: str) -> str:
    """Enclose one document's clean_text as data.

    The closing marker is removed from the document (not escaped) because the
    marker is never meaningful content: clean_text is prose extracted from
    HTML, and a document containing this exact token is either coincidence or
    an attempt to break out of the block. Neither is worth preserving.
    """
    neutralized = report_text.replace(CLOSE_MARKER, "").replace(OPEN_MARKER, "")
    return _user_template().format(report_text=neutralized)
