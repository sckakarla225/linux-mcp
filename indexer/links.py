"""Cross-links between documentation, symbols and registries.

Nothing here guesses: a name with several definitions links to each candidate with a lower
confidence, and a name with no definition in scope is recorded as unresolved.
"""

import re
from dataclasses import dataclass

from indexer.corpus import Corpus
from indexer.docs import Doc, KernelDoc, Mention, Section
from indexer.model import RegistryEntry, SymbolIndex, SymbolRow
from indexer.netlink import NetlinkFamily
from indexer.records import Record

MAX_CANDIDATES = 4
# doc folders whose subject code is fully inside the indexed scope
STALE_CHECK_FOLDERS = ("networking", "netlabel", "netlink")


@dataclass
class MentionRow:
    doc_id: str
    line: int
    raw_text: str
    mention_kind: str
    target_type: str | None
    target_id: str | None
    method: str | None
    confidence: float | None
    stale: bool


def _rank(rows: list[SymbolRow]) -> list[SymbolRow]:
    return sorted(rows, key=lambda r: (r.is_static, not r.path.endswith(".c") and r.kind == "function", r.path))


def _confidence(count: int) -> float:
    return 0.9 if count == 1 else round(max(0.3, 0.8 / count), 2)


class Linker:
    def __init__(self, corpus: Corpus, docs: dict[str, Doc], symbols: SymbolIndex,
                 entries: dict[str, RegistryEntry], files: set[str]):
        self.corpus = corpus
        # every identifier that occurs anywhere in the in-scope source
        self.identifiers: set[str] = set()
        for path, text in corpus.code.items():
            if path.endswith((".c", ".h")):
                self.identifiers.update(re.findall(r"[A-Za-z_]\w{2,}", text))
        self.docs = docs
        self.symbols = symbols
        self.entries = entries
        self.files = files
        self.by_alias: dict[tuple[str, str], list[RegistryEntry]] = {}
        for entry in entries.values():
            for alias in entry.aliases:
                self.by_alias.setdefault((entry.type, alias), []).append(entry)
        self.basenames: dict[str, list[str]] = {}
        for path in corpus.known_paths:
            self.basenames.setdefault(path.rsplit("/", 1)[-1], []).append(path)
        self.snmp_keys = {e.key: e for e in entries.values() if e.type == "snmp"}
        self.sysctl_names = {
            alias: rows for (kind, alias), rows in self.by_alias.items() if kind == "sysctl" and "_" in alias
        }

    # ---- mentions ----

    def _symbol_rows(self, mention: Mention, kinds: tuple[str, ...]) -> list[MentionRow]:
        rows = _rank(self.symbols.find(mention.name, kinds))
        if not rows:
            # A name that the in-scope source never uses, written in a doc about that source,
            # has been renamed or removed. Elsewhere it may simply be outside the scope.
            folder = mention.doc_id.split("/", 1)[0]
            stale = folder in STALE_CHECK_FOLDERS and mention.name not in self.identifiers
            return [MentionRow(mention.doc_id, mention.line, mention.raw_text, mention.kind, None, None, None, None, stale)]
        confidence = _confidence(len(rows))
        return [
            MentionRow(mention.doc_id, mention.line, mention.raw_text, mention.kind, "symbol",
                       row.symbol_id, "name_match", confidence, False)
            for row in rows[:MAX_CANDIDATES]
        ]

    def _registry_rows(self, mention: Mention, entries: list[RegistryEntry], prefix_id: str | None = None) -> list[MentionRow]:
        if prefix_id and len(entries) > 1:
            return [MentionRow(mention.doc_id, mention.line, mention.raw_text, mention.kind, "registry",
                               prefix_id, "name_match", 0.9, False)]
        confidence = _confidence(len(entries))
        return [
            MentionRow(mention.doc_id, mention.line, mention.raw_text, mention.kind, "registry",
                       entry.entry_id, "name_match", confidence, False)
            for entry in entries[:MAX_CANDIDATES]
        ]

    def _path_row(self, mention: Mention) -> MentionRow:
        path = mention.name
        base = (mention.doc_id, mention.line, mention.raw_text, "path")
        if path in self.files:
            return MentionRow(*base, "file", path, "path_match", 1.0, False)
        if path.startswith("Documentation/") and path[len("Documentation/"):] in self.docs:
            return MentionRow(*base, "doc", path[len("Documentation/"):], "path_match", 1.0, False)
        if path.endswith("/") or "." not in path.rsplit("/", 1)[-1]:
            folder = path.rstrip("/") + "/"
            listed = self.corpus.path_is_listed(folder.rstrip("/"))
            exists = any(p.startswith(folder) for p in self.corpus.known_paths) if listed is not None else None
            return MentionRow(*base, None, None, "path_match", None, exists is False)
        listed = self.corpus.path_is_listed(path)
        if listed:
            # exists at the pinned tag but is outside the indexed scope
            return MentionRow(*base, "file", path, "path_match", 1.0, False)
        if listed is None:
            return MentionRow(*base, None, None, None, None, False)
        # the path does not exist at this tag: look for the file under its current location
        candidates = self.basenames.get(path.rsplit("/", 1)[-1], [])
        if len(candidates) == 1:
            return MentionRow(*base, "file", candidates[0], "path_match", 0.5, True)
        return MentionRow(*base, None, None, "path_match", None, True)

    def resolve(self, mentions: list[Mention]) -> list[MentionRow]:
        rows: list[MentionRow] = []
        for mention in mentions:
            kind = mention.kind
            if kind == "function":
                rows += self._symbol_rows(mention, ("function", "macro"))
            elif kind == "struct":
                rows += self._symbol_rows(mention, ("struct", "union", "typedef"))
            elif kind == "macro":
                rows += self._symbol_rows(mention, ("macro", "enum_constant"))
            elif kind == "config":
                entry = self.entries.get(f"kconfig/{mention.name}")
                if entry is not None:
                    rows += self._registry_rows(mention, [entry])
                else:
                    rows.append(MentionRow(mention.doc_id, mention.line, mention.raw_text, kind, None, None, None, None, False))
            elif kind == "netlink_msg":
                found = self.by_alias.get(("registration", mention.name), [])
                if found:
                    mechanism = found[0].attrs.get("mechanism")
                    rows += self._registry_rows(mention, found, f"registration/{mechanism}/{mention.name}")
                else:
                    rows += self._symbol_rows(mention, ("macro", "enum_constant"))
            elif kind == "path":
                rows.append(self._path_row(mention))
            elif kind == "sysctl":
                entry = self.entries.get(f"sysctl/{mention.name}")
                found = [entry] if entry else self.by_alias.get(("sysctl", mention.name.rsplit(".", 1)[-1]), [])
                if found:
                    rows += self._registry_rows(mention, found)
                else:
                    rows.append(MentionRow(mention.doc_id, mention.line, mention.raw_text, kind, None, None, None, None, False))
        return rows

    def registry_mentions(self, section: Section) -> list[MentionRow]:
        """SNMP counter names and sysctl names written as plain words in a section."""
        rows = []
        seen: set[str] = set()
        for offset, line in enumerate(section.text.split("\n")):
            for token in re.findall(r"\b[A-Z][A-Za-z0-9]{5,}\b|\b[a-z][a-z0-9]*_[a-z0-9_]+\b", line):
                if token in seen:
                    continue
                entry = self.snmp_keys.get(token)
                if entry is not None:
                    seen.add(token)
                    rows.append(MentionRow(section.doc_id, section.start_line + offset, token, "counter",
                                           "registry", entry.entry_id, "name_match", 0.9, False))
                    continue
                found = self.sysctl_names.get(token)
                if found and not self.symbols.find(token, ("function",)):
                    seen.add(token)
                    confidence = round(min(0.6, _confidence(len(found))), 2)
                    for entry in found[:MAX_CANDIDATES]:
                        rows.append(MentionRow(section.doc_id, section.start_line + offset, token, "sysctl",
                                               "registry", entry.entry_id, "name_match", confidence, False))
        return rows

    # ---- kernel-doc directives ----

    def kernel_doc_symbols(self, directive: KernelDoc) -> list[SymbolRow]:
        rows = self.symbols.by_path.get(directive.source_path, [])
        if directive.mode in ("functions", "identifiers") and directive.names:
            wanted = set(directive.names.split())
            return [r for r in rows if r.name in wanted and r.kind != "enum_constant"]
        if directive.mode == "doc":
            return []
        documented = [r for r in rows if r.doc_comment and r.kind != "enum_constant"]
        if directive.mode == "export":
            return [r for r in documented if r.is_exported]
        if directive.mode == "internal":
            return [r for r in documented if not r.is_exported]
        return documented

    # ---- records ----

    def _names_to_symbols(self, names: list[str], kinds: tuple[str, ...]) -> list[str]:
        found = []
        for name in names:
            for row in _rank(self.symbols.find(name, kinds))[:2]:
                if row.symbol_id not in found:
                    found.append(row.symbol_id)
        return found

    @staticmethod
    def _normalize_sysctl(key: str) -> str:
        key = re.sub(r"\.(all|default|interface|<dev>|<interface>|\*)(?=\.)", ".*", key)
        return key.replace("<proto>", "*")

    def link_record(self, record: Record, map_type_ops: dict[str, str]) -> str | None:
        """Fill record.attrs with symbol links; return the matching registry entry id."""
        dataset = record.dataset
        attrs = record.attrs
        if dataset == "sysctl":
            candidates = self.by_alias.get(("sysctl", attrs["procname"]), [])
            if not candidates:
                return None
            wanted = self._normalize_sysctl(record.key)
            wanted_root = ".".join(record.key.split(".")[:2])

            def score(entry: RegistryEntry) -> tuple:
                key = self._normalize_sysctl(entry.key)
                same = key == wanted or re.fullmatch(key.replace(".", r"\.").replace("*", r"[^.]+"), wanted) is not None
                return (not same, not entry.key.startswith(wanted_root), not entry.resolved, entry.key)

            best = sorted(candidates, key=score)[0]
            attrs["registry_match"] = "exact_path" if not score(best)[0] else "name_only"
            if len(candidates) > 1:
                attrs["other_candidates"] = [c.entry_id for c in candidates if c is not best][:5]
            return best.entry_id
        if dataset in ("snmp", "xfrm_counter"):
            entry = self.entries.get(f"snmp/{record.key}")
            if entry is None:
                # the doc may write the name without its /proc group prefix
                found = self.by_alias.get(("snmp", record.key), [])
                entry = found[0] if len(found) == 1 else None
            if dataset == "snmp" and attrs.get("functions_mentioned"):
                attrs["symbols"] = self._names_to_symbols(attrs["functions_mentioned"], ("function",))
            return entry.entry_id if entry else None
        if dataset == "net_cachelines":
            struct = self._names_to_symbols([attrs["struct"]], ("struct",))
            attrs["struct_symbol"] = struct[0] if struct else None
            attrs["symbols"] = self._names_to_symbols(attrs.get("functions") or [], ("function", "macro"))[:20]
            return None
        if dataset in ("operstate", "btf_kind", "kfunc_flag"):
            attrs["symbols"] = self._names_to_symbols([record.key], ("macro", "enum_constant"))
            return None
        if dataset == "ethtool_msg":
            attrs["symbols"] = self._names_to_symbols([record.key], ("macro", "enum_constant"))
            return None
        if dataset == "bpf_prog_type":
            names = [attrs["program_type"]] + ([attrs["attach_type"]] if attrs.get("attach_type") else [])
            attrs["symbols"] = self._names_to_symbols(names, ("enum_constant", "macro"))
            return None
        if dataset == "bpf_map_type":
            ops_name = map_type_ops.get(record.key)
            ops = self.symbols.resolve(ops_name, ("global", "ops_instance")) if ops_name else None
            attrs["ops_symbol"] = ops.symbol_id if ops else None
            attrs["implementation_file"] = ops.path if ops else None
            attrs["symbols"] = self._names_to_symbols([record.key], ("enum_constant",))
            for group in ("kernel_helpers", "userspace_calls"):
                for helper in attrs.get(group, []):
                    entry = self.entries.get(f"bpf_helper/{helper['name']}")
                    if entry is not None:
                        helper["registry_id"] = entry.entry_id
            return None
        if dataset == "proc_net_tcp":
            attrs["symbols"] = self._names_to_symbols(attrs.get("implemented_by", []), ("function",))
            return None
        return None

    # ---- netlink ----

    def link_netlink(self, family: NetlinkFamily, genl_commands: dict[str, list[dict]]) -> list[tuple[str, str, str, float]]:
        """Set registration ids and handler symbols on a family's ops. Returns registry_doc_links."""
        doc_links: list[tuple[str, str, str, float]] = []
        genl_entry = None
        for entry in self.entries.values():
            if entry.type == "registration" and entry.attrs.get("mechanism") == "genl":
                commands = {c["cmd"] for c in entry.attrs.get("commands", [])}
                if family.ops and sum(1 for op in family.ops if op.message_constant in commands) >= max(1, len(family.ops) // 3):
                    genl_entry = entry
                    break
        if genl_entry is not None:
            doc_links.append((genl_entry.entry_id, family.spec_doc_id, "netlink_spec", 1.0))
            family.attrs["registration_id"] = genl_entry.entry_id
        for op in family.ops:
            handlers: list[str] = []
            registration_id = None
            constant = op.message_constant
            raw = self.by_alias.get(("registration", constant), [])
            raw = [e for e in raw if e.attrs.get("mechanism") in ("rtnl", "nfnl")]
            if raw:
                mechanism = raw[0].attrs["mechanism"]
                registration_id = raw[0].entry_id if len(raw) == 1 else f"registration/{mechanism}/{constant}"
                for entry in raw:
                    for role in ("doit", "dumpit", "call"):
                        value = entry.attrs.get(role)
                        if isinstance(value, str) and "::" in value and value not in handlers:
                            handlers.append(value)
                    doc_links.append((entry.entry_id, op.doc_id, "netlink_spec", 1.0))
            elif constant in genl_commands:
                for command in genl_commands[constant]:
                    for role in ("doit", "dumpit"):
                        value = command.get(role)
                        if isinstance(value, str) and "::" in value and value not in handlers:
                            handlers.append(value)
                registration_id = genl_entry.entry_id if genl_entry else None
            constant_symbols = self._names_to_symbols([constant], ("enum_constant", "macro"))
            op.attrs["message_constant"] = constant
            op.attrs["message_constant_symbol"] = constant_symbols[0] if constant_symbols else None
            op.attrs["registration_id"] = registration_id
            op.attrs["handler_symbol_ids"] = handlers
        return doc_links
