"""In-memory model shared by the index build steps."""

import bisect
from dataclasses import dataclass, field


@dataclass
class SymbolRow:
    symbol_id: str
    path: str
    name: str
    kind: str
    start_line: int
    end_line: int
    name_line: int
    signature: str
    is_static: bool = False
    is_exported: bool = False
    is_macro_generated: bool = False
    ifdef_guard: str | None = None
    doc_comment: str | None = None
    struct_type: str | None = None
    has_initializer: bool = False
    parent: str | None = None


@dataclass
class RegistryEntry:
    type: str
    key: str
    symbol_id: str | None = None
    path: str | None = None
    line: int | None = None
    resolved: bool = True
    attrs: dict = field(default_factory=dict)
    aliases: list[str] = field(default_factory=list)
    text: str = ""  # searchable text; not stored
    entry_id: str = ""


@dataclass
class RegistryUse:
    entry_id: str
    path: str
    line: int
    symbol_id: str | None
    use_kind: str


CALLABLE_KINDS = ("function", "macro")
DEFINITION_PRIORITY = {"function": 0, "global": 1, "ops_instance": 1, "struct": 2, "union": 2,
                       "enum": 2, "typedef": 3, "macro": 4, "enum_constant": 5}


class SymbolIndex:
    def __init__(self, symbols: list[SymbolRow]):
        self.symbols = symbols
        self.by_id: dict[str, SymbolRow] = {s.symbol_id: s for s in symbols}
        self.by_name: dict[str, list[SymbolRow]] = {}
        self.by_path: dict[str, list[SymbolRow]] = {}
        for symbol in symbols:
            self.by_name.setdefault(symbol.name, []).append(symbol)
            self.by_path.setdefault(symbol.path, []).append(symbol)
        self._starts: dict[str, list[int]] = {}
        self._containers: dict[str, list[SymbolRow]] = {}
        for path, rows in self.by_path.items():
            containers = sorted(
                (r for r in rows if r.kind != "enum_constant"), key=lambda r: (r.start_line, -r.end_line)
            )
            self._containers[path] = containers
            self._starts[path] = [r.start_line for r in containers]

    def enclosing(self, path: str, line: int) -> SymbolRow | None:
        """Innermost non-constant symbol whose range contains the line."""
        containers = self._containers.get(path)
        if not containers:
            return None
        index = bisect.bisect_right(self._starts[path], line) - 1
        best = None
        # ranges rarely nest more than a couple of levels; look back a few entries
        for probe in range(index, max(-1, index - 12), -1):
            row = containers[probe]
            if row.start_line <= line <= row.end_line:
                if best is None or (row.end_line - row.start_line) < (best.end_line - best.start_line):
                    best = row
        return best

    def find(self, name: str, kinds: tuple[str, ...] | None = None, prefer_path: str | None = None) -> list[SymbolRow]:
        rows = self.by_name.get(name, [])
        if kinds:
            rows = [r for r in rows if r.kind in kinds]
        if prefer_path:
            local = [r for r in rows if r.path == prefer_path]
            if local:
                return local
        return rows

    def resolve(self, name: str | None, kinds: tuple[str, ...] | None = None, prefer_path: str | None = None) -> SymbolRow | None:
        """Best single definition for a name: same file first, then a unique or non-static one."""
        if not name:
            return None
        rows = self.find(name, kinds, prefer_path)
        if not rows:
            return None
        if len(rows) == 1:
            return rows[0]
        rows = sorted(rows, key=lambda r: (r.is_static, DEFINITION_PRIORITY.get(r.kind, 9), not r.has_initializer and r.kind == "global", not r.path.endswith(".c"), r.path))
        return rows[0]

    def source_slice(self, code: dict[str, str], symbol: SymbolRow) -> str:
        lines = code[symbol.path].split("\n")
        return "\n".join(lines[symbol.start_line - 1 : symbol.end_line])
