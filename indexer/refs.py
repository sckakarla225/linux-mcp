"""Name-based reference index: every occurrence of an indexed symbol name outside its definition."""

import re

from db import REF_KINDS
from indexer.ctext import LineIndex, strip_comments
from indexer.model import SymbolIndex

FUNCTION, MACRO, GLOBAL, TYPE, TYPEDEF, CONSTANT = 1, 2, 4, 8, 16, 32
KIND_BITS = {
    "function": FUNCTION, "macro": MACRO, "global": GLOBAL, "ops_instance": GLOBAL,
    "struct": TYPE, "union": TYPE, "enum": TYPE, "typedef": TYPEDEF, "enum_constant": CONSTANT,
}
_TOKEN_RE = re.compile(r"(?:\b(struct|union|enum)\s+|(->|\.)\s*)?\b([A-Za-z_]\w*)(\s*\()?")
_INCLUDE_RE = re.compile(r"^[ \t]*#[ \t]*include[^\n]*", re.MULTILINE)
# names too generic to be useful as references
_SKIP_NAMES = {"i", "x", "y", "n", "p", "s", "len", "ret", "err", "val", "data", "size", "name", "type", "flags", "index", "key", "id"}


def iter_refs(code: dict[str, str], symbols: SymbolIndex):
    """Yield (name, path, line, enclosing_symbol_id | None, ref_kind int)."""
    kinds: dict[str, int] = {}
    definitions: set[tuple[str, str, int]] = set()
    for symbol in symbols.symbols:
        if symbol.name in _SKIP_NAMES or len(symbol.name) < 3:
            continue
        kinds[symbol.name] = kinds.get(symbol.name, 0) | KIND_BITS.get(symbol.kind, 0)
        definitions.add((symbol.path, symbol.name, symbol.name_line))
    call, address_of, type_use, other = (REF_KINDS[k] for k in ("call", "address_of", "type_use", "other"))
    for path in sorted(code):
        if not path.endswith((".c", ".h")):
            continue
        text = strip_comments(code[path], strings=True)
        text = _INCLUDE_RE.sub(lambda m: " " * len(m.group(0)), text)
        lines = LineIndex(text)
        seen: set[tuple[str, int, int]] = set()
        for match in _TOKEN_RE.finditer(text):
            name = match.group(3)
            bits = kinds.get(name)
            if bits is None:
                continue
            if match.group(1):
                if not bits & TYPE:
                    continue
                kind = type_use
            elif match.group(2):
                continue  # a member access, not the global name
            else:
                bits &= ~TYPE
                if not bits:
                    continue
                if match.group(4):
                    kind = call if bits & (FUNCTION | MACRO) else other
                elif bits & FUNCTION:
                    kind = address_of
                elif bits == TYPEDEF:
                    kind = type_use
                else:
                    kind = other
            line = lines.line(match.start(3))
            if (path, name, line) in definitions or (name, line, kind) in seen:
                continue
            seen.add((name, line, kind))
            enclosing = symbols.enclosing(path, line)
            if enclosing is None and kind in (call, address_of):
                kind = other  # a prototype or declaration at file scope
            yield name, path, line, enclosing.symbol_id if enclosing else None, kind
