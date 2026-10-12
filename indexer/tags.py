"""Keyword tags for code files, generated from data the index build already has."""

import math
import re

from indexer.aliases import alias_rows

TAGS_PER_FILE = 25
WEAK_SOURCES = {"header_comment", "doc_section"}
MIN_FILES_FOR_WEAK_TAG = 4
MAX_IDF = 5.0
CONCEPT_BOOST = 1.5

# Source weights, strongest first.
WEIGHTS = {
    "maintainers": 3.0,
    "kconfig": 2.5,
    "doc_section": 2.0,
    "registry": 2.0,
    "header_comment": 1.0,
    "symbols": 1.0,
}

STOPWORDS = set(
    """a an and are as at be been but by can could do does for from has have how if in into is it
    its may more most must no not of on one only or other our out should so some such than that
    the their them then there these they this to up use used uses using via was we were what
    when where which will with would you your all any each also about above after again
    linux kernel driver drivers support code file files function functions struct structure
    implementation implemented copyright license gpl author authors version general public
    foundation free software written based see note notes todo fixme inc ltd corp gmbh com org
    net core common generic main new old get set add del init exit alloc free put read write
    static inline void int char unsigned long const return define include module
    networking network subsystem layer protocol interface device devices data type value info
    under terms modify redistribute either option later program distributed hope warranty
    should say unsure enable enables enabled option options config choose here want need
    documentation information please available provides provide allow allows help
    comments overview usage introduction example examples description references background
    summary details design api variables rest contents section following various several
    http https www html org net edu first second also however therefore because between
    university authors author fixes changes revision work works original originally
    table tables list lists entry entries number numbers size sizes time times
    hash tree node nodes""".split()
)

_WORD_RE = re.compile(r"[a-z][a-z0-9]+")


class Tagger:
    def __init__(self):
        rows = alias_rows()
        self.single = {alias: canonical for alias, canonical in rows if " " not in alias and "-" not in alias and "/" not in alias and "." not in alias}
        phrases = [(alias, canonical) for alias, canonical in rows if alias not in self.single]
        self.phrase_re = re.compile(
            r"(?<![a-z0-9])(" + "|".join(re.escape(a) for a, _ in sorted(phrases, key=lambda r: -len(r[0]))) + r")(?![a-z0-9])"
        )
        self.phrase_map = dict(phrases)
        self.terms: dict[str, dict[str, dict[str, float]]] = {}  # path -> tag -> source -> weight

    def add_text(self, path: str, source: str, text: str, weight: float = 1.0) -> None:
        if not text:
            return
        lowered = text.lower()
        bucket = self.terms.setdefault(path, {})
        scale = WEIGHTS[source] * weight
        for match in self.phrase_re.finditer(lowered):
            canonical = self.phrase_map[match.group(1)]
            bucket.setdefault(canonical, {})[source] = bucket.get(canonical, {}).get(source, 0.0) + 2 * scale
        for word in _WORD_RE.findall(lowered.replace("_", " ")):
            tag = self.single.get(word, word)
            if tag in STOPWORDS or len(tag) < 3 or len(tag) > 28:
                continue
            bucket.setdefault(tag, {})[source] = bucket.get(tag, {}).get(source, 0.0) + scale

    def add_term(self, path: str, source: str, term: str, weight: float = 1.0) -> None:
        """Add a whole identifier as one tag (e.g. a sysctl or counter name) plus its words."""
        term = term.lower()
        if 3 <= len(term) <= 40 and term not in STOPWORDS:
            bucket = self.terms.setdefault(path, {})
            bucket.setdefault(term, {})[source] = bucket.get(term, {}).get(source, 0.0) + WEIGHTS[source] * weight
        self.add_text(path, source, term, weight * 0.5)

    def rank(self) -> dict[str, list[tuple[str, float, str]]]:
        """Top tags per file as (tag, score, strongest source), ranked by TF-IDF."""
        document_count = max(1, len(self.terms))
        frequency: dict[str, int] = {}
        for bucket in self.terms.values():
            for tag in bucket:
                frequency[tag] = frequency.get(tag, 0) + 1
        concepts = set(self.single.values()) | set(self.phrase_map.values())
        ranked = {}
        for path, bucket in self.terms.items():
            scored = []
            for tag, sources in bucket.items():
                weak = set(sources) <= WEAK_SOURCES
                # a word seen only in comments or section titles of one or two files is
                # an author, an address or a one-off phrase, not a topic
                if weak and frequency[tag] < MIN_FILES_FOR_WEAK_TAG and tag not in concepts:
                    continue
                term_frequency = 1 + math.log(1 + sum(sources.values()))
                inverse = min(MAX_IDF, math.log(1 + document_count / frequency[tag]))
                boost = CONCEPT_BOOST if tag in concepts else 1.0
                strongest = max(sources, key=lambda s: sources[s])
                scored.append((tag, round(term_frequency * inverse * boost, 3), strongest))
            scored.sort(key=lambda item: (-item[1], item[0]))
            ranked[path] = scored[:TAGS_PER_FILE]
        return ranked


def identifier_words(name: str) -> str:
    return name.replace("_", " ")


def leading_comment(text: str) -> str | None:
    """The comment block at the top of a file, without licence boilerplate."""
    stripped = text.lstrip()
    blocks = []
    while True:
        if stripped.startswith("//"):
            line, _, stripped = stripped.partition("\n")
            blocks.append(line[2:].strip())
        elif stripped.startswith("/*"):
            end = stripped.find("*/")
            if end == -1:
                break
            body = stripped[2:end]
            blocks.append("\n".join(l.strip().lstrip("*").strip() for l in body.split("\n")))
            stripped = stripped[end + 2 :]
        elif stripped.startswith("#") and "Makefile" in stripped[:80] or stripped.startswith("# "):
            line, _, stripped = stripped.partition("\n")
            blocks.append(line.lstrip("# ").strip())
        else:
            break
        stripped = stripped.lstrip()
        if len(blocks) >= 3:
            break
    text = "\n".join(b for b in blocks if b)
    # old-style headers end in author lists and changelogs; keep what comes before them
    cut = re.search(r"^\s*(Fixes|Changes|Changelog|Authors?|History|Version|Derived from|Based on|Credits|Maintainers?)\b.*$", text, re.MULTILINE | re.IGNORECASE)
    if cut and cut.start() > 0:
        text = text[: cut.start()]
    lines = [
        l for l in text.split("\n")
        if l and not re.search(r"SPDX-License-Identifier|Copyright|\(c\)|GNU General Public|Free Software|WARRANTY|Authors?:|^\s*<|@[\w.-]+\.\w+|redistribute|either version", l, re.IGNORECASE)
    ]
    result = "\n".join(lines).strip()
    return result[:1200] or None


def kernel_doc_summary(doc_comment: str | None) -> str:
    if not doc_comment:
        return ""
    match = re.search(r"/\*\*\s*\n?\s*\*?\s*(?:struct\s+|enum\s+|union\s+)?[\w()]+\s*-\s*(.+)", doc_comment)
    return match.group(1).strip() if match else ""
