"""Controlled vocabularies for the target field: the sector list and its synonym
map, plus the country gazetteer the §7 baseline searches with.

normalize_sector is applied to both sides before scoring. Why the tables look
the way they do: docs/DECISIONS.md#vocab
"""

from __future__ import annotations

import re

# The scoring vocabulary. Gold annotations use these strings exactly; model
# output is mapped onto them via SECTOR_SYNONYMS.
SECTORS: frozenset[str] = frozenset(
    {
        # SOCI Act sectors
        "communications",
        "data storage and processing",
        "defence industry",
        "energy",
        "financial services",
        "food and grocery",
        "health care",
        "higher education and research",
        "space technology",
        "transport",
        "water and sewerage",
        # Common in CTI reporting, absent from SOCI
        "government",
        "manufacturing",
        "technology",
        "media",
        "retail",
        "legal",
        "military",
        "ngo",
    }
)

# Surface forms -> vocabulary. Unambiguous mappings only: "utilities" (energy?
# water?) would fabricate agreement between model and annotator.
SECTOR_SYNONYMS: dict[str, str] = {
    "telecom": "communications",
    "telecoms": "communications",
    "telecommunications": "communications",
    "telco": "communications",
    "isp": "communications",
    "cloud": "data storage and processing",
    "cloud services": "data storage and processing",
    "data centre": "data storage and processing",
    "data center": "data storage and processing",
    "defense industry": "defence industry",
    "defence": "defence industry",
    "defense": "defence industry",
    "defence industrial base": "defence industry",
    "defense industrial base": "defence industry",
    "oil and gas": "energy",
    "oil & gas": "energy",
    "power": "energy",
    "electricity": "energy",
    "electric power": "energy",
    "nuclear": "energy",
    "utilities": "energy",
    "finance": "financial services",
    "financial": "financial services",
    "financial services and markets": "financial services",
    "banking": "financial services",
    "banks": "financial services",
    "insurance": "financial services",
    "fintech": "financial services",
    "cryptocurrency": "financial services",
    "food": "food and grocery",
    "agriculture": "food and grocery",
    "healthcare": "health care",
    "health": "health care",
    "health care and medical": "health care",
    "hospitals": "health care",
    "medical": "health care",
    "pharmaceutical": "health care",
    "pharmaceuticals": "health care",
    "education": "higher education and research",
    "universities": "higher education and research",
    "university": "higher education and research",
    "academia": "higher education and research",
    "research": "higher education and research",
    "space": "space technology",
    "aerospace": "space technology",
    "satellite": "space technology",
    "aviation": "transport",
    "airlines": "transport",
    "airline": "transport",
    "maritime": "transport",
    "shipping": "transport",
    "logistics": "transport",
    "rail": "transport",
    "railway": "transport",
    "water": "water and sewerage",
    "wastewater": "water and sewerage",
    "water utilities": "water and sewerage",
    "water treatment": "water and sewerage",
    "public sector": "government",
    "public administration": "government",
    "federal government": "government",
    "local government": "government",
    "diplomatic": "government",
    "industrial": "manufacturing",
    "it": "technology",
    "software": "technology",
    "information technology": "technology",
    "tech": "technology",
    "telecommunications and technology": "technology",
    "news media": "media",
    "journalism": "media",
    "press": "media",
    "law firms": "legal",
    "law": "legal",
    "defense contractors": "defence industry",
    "armed forces": "military",
    "civil society": "ngo",
    "non-profit": "ngo",
    "nonprofit": "ngo",
    "ngos": "ngo",
}

# Trailing nouns that add nothing. Stripped only *after* a direct lookup
# fails, so "defence industry" is not truncated to "defence".
_TRAILING_NOUNS = (" sector", " sectors", " industry", " industries", " organisations",
                   " organizations", " organisation", " organization", " companies",
                   " entities", " providers", " operators")


def normalize_sector(sector: str) -> str:
    """Map a sector string onto SECTORS, or return it normalized but unmapped.

    Applied to both gold and prediction. Returning the unmapped string rather
    than dropping it is what makes off-vocabulary answers countable (see
    `is_in_vocabulary`) instead of invisible.
    """
    text = " ".join(sector.strip().casefold().split())
    if not text:
        return ""

    if text in SECTORS:
        return text
    if text in SECTOR_SYNONYMS:
        return SECTOR_SYNONYMS[text]

    for suffix in _TRAILING_NOUNS:
        if text.endswith(suffix):
            stripped = text[: -len(suffix)].strip()
            if stripped in SECTORS:
                return stripped
            if stripped in SECTOR_SYNONYMS:
                return SECTOR_SYNONYMS[stripped]
            text = stripped
            break

    return text


def is_in_vocabulary(normalized_sector: str) -> bool:
    return normalized_sector in SECTORS


# ---------- countries ----------

# Name/demonym -> ISO 3166-1 alpha-2, for the baseline's target extraction.
# Deliberately partial and hand-written, and kept visible in one place:
# docs/DECISIONS.md#vocab. Case-insensitive; two-letter abbreviations are
# handled separately below because "US" folded also matches the pronoun.
COUNTRY_NAMES: dict[str, str] = {
    "united states": "US", "america": "US", "american": "US",
    "united kingdom": "GB", "britain": "GB", "british": "GB", "england": "GB",
    "australia": "AU", "australian": "AU",
    "new zealand": "NZ",
    "canada": "CA", "canadian": "CA",
    "ukraine": "UA", "ukrainian": "UA",
    "russia": "RU", "russian": "RU",
    "china": "CN", "chinese": "CN",
    "taiwan": "TW", "taiwanese": "TW",
    "hong kong": "HK",
    "japan": "JP", "japanese": "JP",
    "south korea": "KR", "north korea": "KP",
    "india": "IN", "indian": "IN",
    "pakistan": "PK",
    "iran": "IR", "iranian": "IR",
    "israel": "IL", "israeli": "IL",
    "saudi arabia": "SA", "united arab emirates": "AE", "qatar": "QA",
    "kuwait": "KW", "jordan": "JO", "lebanon": "LB", "iraq": "IQ", "syria": "SY",
    "turkey": "TR", "turkish": "TR", "egypt": "EG",
    "germany": "DE", "german": "DE",
    "france": "FR", "french": "FR",
    "italy": "IT", "italian": "IT",
    "spain": "ES", "spanish": "ES",
    "netherlands": "NL", "dutch": "NL",
    "belgium": "BE", "poland": "PL", "polish": "PL",
    "sweden": "SE", "norway": "NO", "finland": "FI", "denmark": "DK",
    "switzerland": "CH", "austria": "AT", "ireland": "IE", "portugal": "PT",
    "czech republic": "CZ", "czechia": "CZ", "slovakia": "SK", "hungary": "HU",
    "romania": "RO", "bulgaria": "BG", "greece": "GR", "serbia": "RS",
    "croatia": "HR", "slovenia": "SI", "estonia": "EE", "latvia": "LV",
    "lithuania": "LT", "belarus": "BY", "moldova": "MD",
    "georgia": "GE", "armenia": "AM", "azerbaijan": "AZ",
    "kazakhstan": "KZ", "uzbekistan": "UZ", "mongolia": "MN",
    "singapore": "SG", "malaysia": "MY", "thailand": "TH",
    "vietnam": "VN", "vietnamese": "VN", "philippines": "PH",
    "indonesia": "ID", "myanmar": "MM", "cambodia": "KH", "laos": "LA",
    "bangladesh": "BD", "sri lanka": "LK", "nepal": "NP", "afghanistan": "AF",
    "brazil": "BR", "brazilian": "BR", "mexico": "MX", "argentina": "AR",
    "chile": "CL", "colombia": "CO",
    "south africa": "ZA", "nigeria": "NG", "kenya": "KE",
}

# Case-sensitive: lowercase "us"/"in"/"it" are a pronoun and prepositions.
COUNTRY_ABBREVIATIONS: dict[str, str] = {
    "US": "US", "U.S.": "US", "USA": "US", "U.S.A.": "US",
    "UK": "GB", "U.K.": "GB",
    "UAE": "AE",
    "PRC": "CN", "ROK": "KR", "DPRK": "KP",
    "NZ": "NZ",
}


def _alternation(terms) -> str:
    """Longest-first so "south korea" wins over "korea"-style prefixes and
    "U.S.A." is not consumed by "U.S.". Escaped because the abbreviations
    contain dots."""
    return "|".join(re.escape(term) for term in sorted(terms, key=len, reverse=True))


# \b works for terms bounded by letters; terms ending in "." need a lookahead,
# since there is no word boundary between "." and a following space.
COUNTRY_NAME_RE = re.compile(rf"\b(?:{_alternation(COUNTRY_NAMES)})\b", re.IGNORECASE)
COUNTRY_ABBREVIATION_RE = re.compile(rf"\b(?:{_alternation(COUNTRY_ABBREVIATIONS)})(?![\w-])")


def find_countries(text: str) -> set[str]:
    """ISO codes for every country name or abbreviation literally present."""
    found = {COUNTRY_NAMES[match.group(0).casefold()] for match in COUNTRY_NAME_RE.finditer(text)}
    found |= {COUNTRY_ABBREVIATIONS[m.group(0)] for m in COUNTRY_ABBREVIATION_RE.finditer(text)}
    return found


# Built from the vocabulary and its synonyms, longest-first, so the baseline
# and the scorer cannot drift.
_SECTOR_SURFACE_FORMS = sorted(
    set(SECTORS) | set(SECTOR_SYNONYMS), key=len, reverse=True
)
SECTOR_RE = re.compile(rf"\b(?:{_alternation(_SECTOR_SURFACE_FORMS)})\b", re.IGNORECASE)


def find_sectors(text: str) -> set[str]:
    """Normalized sectors for every vocabulary term literally present."""
    return {normalize_sector(match.group(0)) for match in SECTOR_RE.finditer(text)}
