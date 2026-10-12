"""Text-level helpers for C sources: comment stripping, macro call matching, initializers.

Registries are built from these rather than from the syntax tree, because registration
macros (`SNMP_MIB_ITEM`, `EXPORT_SYMBOL`, `module_init`, `TRACE_EVENT`, ...) and large
designated initializers are exactly where a C parser without a preprocessor is least reliable.
"""

import bisect
import re
from dataclasses import dataclass

_COMMENT_OR_STRING_RE = re.compile(
    r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.DOTALL
)


def _blank_keep_newlines(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def strip_comments(text: str, strings: bool = False) -> str:
    """Blank out comments (and optionally string/char literals), keeping offsets and lines."""

    def replace(match: re.Match) -> str:
        token = match.group(0)
        if token.startswith(("/*", "//")):
            return _blank_keep_newlines(token)
        if strings:
            return token[0] + _blank_keep_newlines(token[1:-1]) + token[-1]
        return token

    return _COMMENT_OR_STRING_RE.sub(replace, text)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


class LineIndex:
    """Offset to line number lookups for one text."""

    def __init__(self, text: str):
        self._starts = [0]
        find = text.find
        position = find("\n")
        while position != -1:
            self._starts.append(position + 1)
            position = find("\n", position + 1)

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self._starts, offset)


_OPEN = {"(": ")", "{": "}", "[": "]"}
_CLOSE = {")", "}", "]"}


def matching_close(text: str, open_offset: int) -> int:
    """Offset of the bracket closing the one at open_offset, or -1. Skips string literals."""
    depth = 0
    index = open_offset
    length = len(text)
    while index < length:
        char = text[index]
        if char in _OPEN:
            depth += 1
        elif char in _CLOSE:
            depth -= 1
            if depth == 0:
                return index
        elif char == '"' or char == "'":
            end = index + 1
            while end < length and text[end] != char:
                end += 2 if text[end] == "\\" else 1
            index = end
        index += 1
    return -1


def split_top_level(text: str, separator: str = ",") -> list[str]:
    """Split on a separator that is not nested in brackets or string literals."""
    parts = []
    depth = 0
    start = 0
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in _OPEN:
            depth += 1
        elif char in _CLOSE:
            depth -= 1
        elif char == '"' or char == "'":
            end = index + 1
            while end < length and text[end] != char:
                end += 2 if text[end] == "\\" else 1
            index = end
        elif char == separator and depth == 0:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    parts.append(text[start:])
    return [part.strip() for part in parts]


@dataclass
class Call:
    name: str
    args: list[str]
    offset: int
    end: int
    line: int


def find_calls(text: str, names_pattern: str, lines: LineIndex | None = None) -> list[Call]:
    """Find `name(args)` for names matching a regex. `text` should have comments stripped."""
    lines = lines or LineIndex(text)
    calls = []
    for match in re.finditer(r"\b(" + names_pattern + r")\s*\(", text):
        open_offset = match.end() - 1
        close = matching_close(text, open_offset)
        if close == -1:
            continue
        inner = text[open_offset + 1 : close]
        args = split_top_level(inner) if inner.strip() else []
        calls.append(Call(match.group(1), args, match.start(), close + 1, lines.line(match.start())))
    return calls


def unquote(text: str) -> str | None:
    """Value of a C string literal (adjacent literals concatenated), or None."""
    text = text.strip()
    pieces = re.findall(r'"((?:\\.|[^"\\])*)"', text)
    if not pieces or re.sub(r'"(?:\\.|[^"\\])*"', "", text).strip():
        return None
    return "".join(pieces)


def bare_identifier(expression: str) -> str | None:
    """The identifier in `x`, `&x`, `(cast)x`, `&x[0]`, `x.y`; None for anything else."""
    expression = expression.strip()
    expression = re.sub(r"^\(\s*[\w\s\*]+\)\s*", "", expression)  # leading cast
    expression = expression.lstrip("&* ").strip()
    match = re.fullmatch(r"\(?\s*([A-Za-z_]\w*)\s*\)?(?:\[[^\]]*\])?", expression)
    return match.group(1) if match else None


def parse_initializer(text: str):
    """Parse a brace initializer into nested Python data.

    `{ .a = x, .b = { .c = y } }` becomes {"a": "x", "b": {"c": "y"}}; positional elements
    become a list; `[IDX] = v` entries are keyed by "[IDX]". Preprocessor lines inside the
    initializer are dropped, so every #ifdef branch contributes its entries.
    """
    text = "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))
    text = text.strip()
    if not text.startswith("{"):
        return text
    close = matching_close(text, 0)
    if close == -1:
        return text
    items = [item for item in split_top_level(text[1:close]) if item]
    designated = {}
    positional = []
    for item in items:
        match = re.match(r"^((?:\.\w+|\[[^\]]+\])+)\s*=\s*(.*)$", item, re.DOTALL)
        if match:
            key = match.group(1)
            key = key[1:] if key.startswith(".") and "[" not in key and key.count(".") == 1 else key
            designated[key] = parse_initializer(match.group(2))
        else:
            positional.append(parse_initializer(item))
    if designated and not positional:
        return designated
    if positional and not designated:
        return positional
    return {"_positional": positional, **designated} if positional else designated


def initializer_of(source_slice: str):
    """Parse the initializer of a declaration given its source text (`type name = {...};`)."""
    stripped = strip_comments(source_slice)
    depth = 0
    for index, char in enumerate(stripped):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "=" and depth == 0:
            return parse_initializer(stripped[index + 1 :].strip().rstrip(";").strip())
    return None
