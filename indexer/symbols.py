"""Builds the symbol table for every in-scope source file."""

from indexer.cparse import extract_symbols
from indexer.model import SymbolIndex, SymbolRow


def build_symbols(code: dict[str, str]) -> tuple[SymbolIndex, dict[str, int]]:
    rows: list[SymbolRow] = []
    stats = {"files": 0, "parse_error_regions": 0}
    for path in sorted(code):
        if not path.endswith((".c", ".h")):
            continue
        parsed, errors = extract_symbols(code[path])
        stats["files"] += 1
        stats["parse_error_regions"] += errors
        seen: set[tuple[str, int]] = set()
        unique = []
        for symbol in parsed:
            if (symbol.name, symbol.start_line) in seen:
                continue
            seen.add((symbol.name, symbol.start_line))
            unique.append(symbol)
        # a forward declaration ("static struct genl_family x;") is not the definition
        initialized = {s.name for s in unique if s.kind == "global" and s.has_initializer}
        unique = [
            s for s in unique
            if not (s.kind == "global" and not s.has_initializer and s.name in initialized)
        ]
        counts: dict[str, int] = {}
        for symbol in unique:
            counts[symbol.name] = counts.get(symbol.name, 0) + 1
        for symbol in unique:
            symbol_id = f"{path}::{symbol.name}"
            if counts[symbol.name] > 1:
                symbol_id += f"@{symbol.start_line}"
            rows.append(
                SymbolRow(
                    symbol_id=symbol_id, path=path, name=symbol.name, kind=symbol.kind,
                    start_line=symbol.start_line, end_line=symbol.end_line,
                    name_line=symbol.name_line, signature=symbol.signature,
                    is_static=symbol.is_static, is_macro_generated=symbol.is_macro_generated,
                    ifdef_guard=symbol.ifdef_guard, doc_comment=symbol.doc_comment,
                    struct_type=symbol.struct_type, has_initializer=symbol.has_initializer,
                    parent=symbol.parent,
                )
            )
    return SymbolIndex(rows), stats
