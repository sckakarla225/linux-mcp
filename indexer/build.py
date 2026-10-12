"""Builds index.db from torvalds/linux at the pinned ref.

Everything is fetched through the GitHub API (tree listings) and raw content URLs. File
contents are used to build the index and then discarded; index.db stores identifiers, line
ranges, metadata, tags and links only.
"""

import json
import math
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import db
import scope
from config import GITHUB_REF, GITHUB_REPO
from github import GitHubClient
from indexer import corpus as corpus_module
from indexer import netlink as netlink_module
from indexer.aliases import alias_rows
from indexer.buildsys import maintainers_for, parse_maintainers
from indexer.docs import Doc, extract_mentions, parse_doc
from indexer.links import Linker
from indexer.records import Record, extract_records
from indexer.refs import iter_refs
from indexer.registries import RegistryBuilder
from indexer.symbols import build_symbols
from indexer.tags import Tagger, identifier_words, kernel_doc_summary, leading_comment

FTS_EXCLUDED_REGISTRY_TYPES = {"export"}


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


class Timer:
    def __init__(self):
        self.started = time.time()
        self.last = self.started

    def step(self, message: str) -> None:
        now = time.time()
        log(f"[{now - self.started:6.1f}s] {message} ({now - self.last:.1f}s)")
        self.last = now


def _dedupe_records(records: list[Record]) -> list[Record]:
    seen: dict[str, int] = {}
    for record in records:
        count = seen.get(record.record_id, 0)
        seen[record.record_id] = count + 1
        if count:
            record.key = f"{record.key}@{record.line}"
    return records


def build(output: Path, cache_dir: Path | None = None) -> dict:
    timer = Timer()
    client = GitHubClient(cache_dir=cache_dir, max_connections=corpus_module.FETCH_WORKERS)
    log(f"Building {output} from {GITHUB_REPO} @ {GITHUB_REF}")
    corpus = corpus_module.load(client)
    timer.step(f"fetched {len(corpus.docs)} docs and {len(corpus.code)} code files ({client.requests} requests)")

    # ---- documentation ----
    docs: dict[str, Doc] = {}
    mentions = []
    kernel_docs = []
    records: list[Record] = []
    families = []
    for doc_path, text in sorted(corpus.docs.items()):
        doc = parse_doc(doc_path, text)
        docs[doc_path] = doc
        for section in doc.sections:
            found, directives = extract_mentions(section)
            mentions += found
            kernel_docs += directives
        records += extract_records(doc, text)
        if doc.format == "yaml" and "/specs/" in doc_path:
            families.append(netlink_module.parse_spec(doc_path, text))
    records = _dedupe_records(records)
    sections = [section for doc in docs.values() for section in doc.sections]
    timer.step(f"parsed docs: {len(sections)} sections, {len(records)} records, {len(families)} netlink families")

    # ---- symbols and registries ----
    symbols, symbol_stats = build_symbols(corpus.code)
    timer.step(f"extracted {len(symbols.symbols)} symbols ({symbol_stats['parse_error_regions']} unparsed regions)")
    kconfig_paths = sorted(p for p in corpus.code if scope.file_type(p) == "kconfig")
    makefile_paths = sorted(p for p in corpus.code if scope.file_type(p) == "makefile")
    registries = RegistryBuilder(corpus.code, symbols, kconfig_paths, makefile_paths)
    registries.build_all()
    entries = registries.entries
    timer.step(f"built {len(entries)} registry entries, {len(registries.uses)} uses")

    # ---- links ----
    files = set(corpus.code)
    linker = Linker(corpus, docs, symbols, entries, files)
    mention_rows = linker.resolve(mentions)
    for section in sections:
        if section.doc_path.endswith(".rst"):
            mention_rows += linker.registry_mentions(section)
    symbol_doc_links: dict[tuple[str, str], tuple[str, float]] = {}
    registry_doc_links: dict[tuple[str, str], tuple[str, float]] = {}

    def link_symbol(symbol_id: str, doc_id: str, method: str, confidence: float) -> None:
        current = symbol_doc_links.get((symbol_id, doc_id))
        if current is None or confidence > current[1]:
            symbol_doc_links[(symbol_id, doc_id)] = (method, confidence)

    def link_registry(entry_id: str, doc_id: str, method: str, confidence: float) -> None:
        current = registry_doc_links.get((entry_id, doc_id))
        if current is None or confidence > current[1]:
            registry_doc_links[(entry_id, doc_id)] = (method, confidence)

    for row in mention_rows:
        if row.target_type == "symbol":
            link_symbol(row.target_id, row.doc_id, row.method, row.confidence)
        elif row.target_type == "registry" and row.target_id in entries:
            link_registry(row.target_id, row.doc_id, "exact_name", row.confidence)
    for directive in kernel_docs:
        for symbol in linker.kernel_doc_symbols(directive):
            link_symbol(symbol.symbol_id, directive.doc_id, "kernel_doc_directive", 1.0)
    record_registry: dict[str, str | None] = {}
    for record in records:
        registry_id = linker.link_record(record, registries.map_type_ops)
        record_registry[record.record_id] = registry_id
        if registry_id:
            link_registry(registry_id, record.doc_id, "exact_name", 1.0)
        if record.dataset == "net_cachelines":
            for symbol_id in [record.attrs.get("struct_symbol")] + record.attrs.get("symbols", []):
                if symbol_id:
                    link_symbol(symbol_id, record.doc_id, "net_cachelines", 0.8)
    for family in families:
        for entry_id, doc_id, method, confidence in linker.link_netlink(family, registries.genl_commands):
            link_registry(entry_id, doc_id, method, confidence)
    # bpf helpers documented in map docs: sections titled "bpf_xxx()"
    for section in sections:
        for name in re.findall(r"\b(bpf_[a-z0-9_]+)\(\)", section.heading):
            if f"bpf_helper/{name}" in entries:
                link_registry(f"bpf_helper/{name}", section.doc_id, "exact_name", 0.9)
    # Kconfig help text that points at a doc file
    for entry in entries.values():
        if entry.type == "kconfig":
            for path in re.findall(r"Documentation/([\w./-]+\.(?:rst|txt|yaml))", entry.attrs.get("help") or ""):
                if path in docs:
                    link_registry(entry.entry_id, docs[path].sections[0].doc_id, "kconfig_help", 1.0)
    timer.step(
        f"linked: {len(mention_rows)} mentions, {len(symbol_doc_links)} symbol-doc links, "
        f"{len(registry_doc_links)} registry-doc links"
    )

    # ---- file metadata and tags ----
    code_paths = sorted(corpus.code)
    maintainer_sections = parse_maintainers(corpus.extra["MAINTAINERS"])
    maintainers = maintainers_for(maintainer_sections, code_paths)
    section_by_name = {s.name: s for s in maintainer_sections}
    headers = {path: leading_comment(corpus.code[path]) for path in code_paths}
    section_by_id = {section.doc_id: section for section in sections}
    tagger = Tagger()
    for path in code_paths:
        for name in [n for n in maintainers.get(path, []) if n != "THE REST"][:3]:
            tagger.add_text(path, "maintainers", name)
            for keyword in section_by_name[name].keywords:
                tagger.add_text(path, "maintainers", re.sub(r"\\[a-zA-Z]|[^A-Za-z0-9_ ]", " ", keyword), 0.5)
        config = registries.file_config.get(path)
        option = entries.get(f"kconfig/{config}") if config else None
        if option is not None:
            tagger.add_text(path, "kconfig", option.attrs.get("prompt") or "")
            tagger.add_text(path, "kconfig", option.attrs.get("help") or "", 0.3)
        tagger.add_text(path, "header_comment", headers[path] or "")
        rows = symbols.by_path.get(path, [])
        chosen = [r for r in rows if (r.is_exported or r.doc_comment) and r.kind in ("function", "struct", "global", "ops_instance")]
        if not chosen:
            chosen = [r for r in rows if r.kind in ("function", "struct")][:60]
        for row in chosen:
            tagger.add_text(path, "symbols", identifier_words(row.name))
            tagger.add_text(path, "header_comment", kernel_doc_summary(row.doc_comment), 0.5)
    for (symbol_id, doc_id), (_, confidence) in symbol_doc_links.items():
        section = section_by_id.get(doc_id)
        if section is not None:
            tagger.add_text(symbol_id.split("::", 1)[0], "doc_section", section.heading, confidence * 0.5)
    for row in mention_rows:
        if row.target_type == "file" and row.target_id in files:
            section = section_by_id.get(row.doc_id)
            if section is not None:
                tagger.add_text(row.target_id, "doc_section", f"{section.heading} {docs[section.doc_path].title}")
    for directive in kernel_docs:
        section = section_by_id.get(directive.doc_id)
        if directive.source_path in files and section is not None:
            tagger.add_text(directive.source_path, "doc_section", f"{section.heading} {docs[section.doc_path].title}")
    for entry in entries.values():
        if not entry.path or entry.path not in files:
            continue
        if entry.type == "sysctl":
            tagger.add_term(entry.path, "registry", entry.attrs["procname"])
        elif entry.type == "snmp":
            tagger.add_term(entry.path, "registry", entry.key, 0.5)
        elif entry.type == "tracepoint":
            tagger.add_term(entry.path, "registry", entry.key)
        elif entry.type == "registration" and entry.attrs.get("mechanism") in ("rtnl", "nfnl"):
            tagger.add_term(entry.path, "registry", entry.attrs["msg_type"])
        elif entry.type == "registration" and entry.attrs.get("mechanism") == "genl" and entry.attrs.get("family"):
            tagger.add_term(entry.path, "registry", entry.attrs["family"])
    tags = tagger.rank()
    timer.step(f"tagged {len(tags)} files")

    # ---- write ----
    connection = db.create(output)
    connection.executemany(
        "INSERT INTO docs VALUES (?,?,?,?,?,?,?)",
        [
            (d.doc_path, d.folder, d.format, d.title, d.line_count,
             corpus.blob_sha.get(f"Documentation/{d.doc_path}"), d.cluster)
            for d in docs.values()
        ],
    )
    for rowid, section in enumerate(sections, start=1):
        connection.execute(
            "INSERT INTO doc_sections(rowid, doc_id, doc_path, heading, level, parent_doc_id, start_line, end_line) VALUES (?,?,?,?,?,?,?,?)",
            (rowid, section.doc_id, section.doc_path, section.heading, section.level,
             section.parent_doc_id, section.start_line, section.end_line),
        )
        connection.execute(
            "INSERT INTO doc_sections_fts(rowid, heading, body) VALUES (?,?,?)",
            (rowid, f"{section.heading} {docs[section.doc_path].title}", section.text),
        )
    connection.executemany(
        "INSERT INTO doc_mentions VALUES (?,?,?,?,?,?,?,?,?)",
        [(r.doc_id, r.line, r.raw_text, r.mention_kind, r.target_type, r.target_id, r.method,
          r.confidence, int(r.stale)) for r in mention_rows],
    )
    connection.executemany(
        "INSERT INTO doc_kernel_doc VALUES (?,?,?,?)",
        [(k.doc_id, k.source_path, k.mode, k.names) for k in kernel_docs],
    )
    connection.executemany(
        "INSERT INTO doc_records VALUES (?,?,?,?,?,?,?,?)",
        [(r.record_id, r.doc_id, r.line, r.end_line, r.dataset, r.key, db.dumps(r.attrs),
          record_registry.get(r.record_id)) for r in records],
    )
    aliases: list[tuple[str, str, str]] = []
    fts_rows: list[tuple[str, str, str, str, str]] = []
    for record in records:
        aliases += [(record.dataset, alias, record.record_id) for alias in dict.fromkeys(record.aliases) if alias and alias != record.key]
        fts_rows.append((record.record_id, "record", record.dataset, record.key, record.text))
    for family in families:
        connection.execute(
            "INSERT INTO netlink_families VALUES (?,?,?,?,?,?)",
            (family.family, family.spec_doc_id, family.protocol, family.uapi_header,
             db.dumps(family.generated_code), db.dumps(family.attrs)),
        )
        aliases.append(("netlink", family.name, f"netlink/{family.family}"))
        for op in family.ops:
            ref_id = f"netlink/{family.family}/{op.op}"
            connection.execute(
                "INSERT INTO netlink_ops VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (family.family, op.op, op.value, op.doc_id, op.doc, db.dumps(op.do_request_attrs),
                 db.dumps(op.do_reply_attrs), db.dumps(op.dump_attrs), op.attrs.get("registration_id"),
                 db.dumps(op.attrs.get("handler_symbol_ids", [])), db.dumps(op.attrs)),
            )
            aliases.append(("netlink", op.message_constant, ref_id))
            aliases.append(("netlink", op.op, ref_id))
            fts_rows.append((ref_id, "record", "netlink", f"{family.family} {op.op} {op.message_constant}", f"{family.name} netlink {op.doc}"))
        for attribute in family.attributes:
            ref_id = f"netlink_attr/{family.family}/{attribute.attr_set}/{attribute.name}"
            connection.execute(
                "INSERT OR IGNORE INTO netlink_attrs VALUES (?,?,?,?,?,?,?)",
                (family.family, attribute.attr_set, attribute.name, attribute.type, attribute.doc_id,
                 attribute.doc, db.dumps(attribute.attrs)),
            )
            aliases.append(("netlink_attr", attribute.name, ref_id))
            if attribute.doc:
                fts_rows.append((ref_id, "record", "netlink_attr", f"{family.family} {attribute.attr_set} {attribute.name}", attribute.doc))

    file_rowid = {}
    for rowid, path in enumerate(code_paths, start=1):
        file_rowid[path] = rowid
        connection.execute(
            "INSERT INTO files(rowid, path, area, subsystem, file_type, line_count, blob_sha, kconfig, maintainers, header_comment) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (rowid, path, scope.code_area(path), scope.subsystem(path), scope.file_type(path),
             corpus.code[path].count("\n") + (0 if corpus.code[path].endswith("\n") else 1),
             corpus.blob_sha.get(path), registries.file_config.get(path),
             db.dumps(maintainers.get(path, [])), headers[path]),
        )
        file_tags = tags.get(path, [])
        connection.executemany(
            "INSERT INTO file_tags VALUES (?,?,?,?)", [(path, tag, score, source) for tag, score, source in file_tags]
        )
        connection.execute(
            "INSERT INTO files_fts(rowid, path, tags, header_comment) VALUES (?,?,?,?)",
            (rowid, path, " ".join(tag for tag, _, _ in file_tags), headers[path] or ""),
        )
    connection.executemany("INSERT INTO tag_aliases VALUES (?,?)", alias_rows())

    symbol_rowid = {}
    for rowid, symbol in enumerate(symbols.symbols, start=1):
        symbol_rowid[symbol.symbol_id] = rowid
    connection.executemany(
        "INSERT INTO symbols(rowid, symbol_id, path, name, kind, start_line, end_line, signature, is_static, is_exported, is_macro_generated, ifdef_guard, doc_comment) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            (symbol_rowid[s.symbol_id], s.symbol_id, s.path, s.name, s.kind, s.start_line, s.end_line,
             s.signature, int(s.is_static), int(s.is_exported), int(s.is_macro_generated),
             s.ifdef_guard, s.doc_comment)
            for s in symbols.symbols
        ],
    )
    connection.executemany(
        "INSERT INTO symbols_fts(rowid, name, signature, doc_comment) VALUES (?,?,?,?)",
        [(symbol_rowid[s.symbol_id], s.name, s.signature, s.doc_comment or "") for s in symbols.symbols],
    )
    connection.executemany(
        "INSERT INTO symbol_doc_links VALUES (?,?,?,?)",
        [(symbol_id, doc_id, method, confidence) for (symbol_id, doc_id), (method, confidence) in symbol_doc_links.items()],
    )

    for entry in entries.values():
        connection.execute(
            "INSERT INTO registry_entries VALUES (?,?,?,?,?,?,?,?)",
            (entry.entry_id, entry.type, entry.key, entry.symbol_id, entry.path, entry.line,
             int(entry.resolved), db.dumps(entry.attrs)),
        )
        aliases += [(entry.type, alias, entry.entry_id) for alias in dict.fromkeys(entry.aliases) if alias and alias != entry.key]
        if entry.type not in FTS_EXCLUDED_REGISTRY_TYPES:
            fts_rows.append((entry.entry_id, "registry", entry.type, entry.key, entry.text))
    connection.executemany(
        "INSERT INTO registry_uses VALUES (?,?,?,?,?)",
        [(u.entry_id, u.path, u.line, u.symbol_id, u.use_kind) for u in registries.uses],
    )
    connection.executemany(
        "INSERT INTO registry_doc_links VALUES (?,?,?,?)",
        [(entry_id, doc_id, method, confidence) for (entry_id, doc_id), (method, confidence) in registry_doc_links.items()],
    )
    connection.executemany("INSERT INTO lookup_aliases VALUES (?,?,?)", sorted(set(aliases)))
    connection.executemany("INSERT INTO registry_fts VALUES (?,?,?,?,?)", fts_rows)
    timer.step("wrote docs, files, symbols and registries")

    # ---- references ----
    name_ids: dict[str, int] = {}
    name_counts: dict[str, int] = {}
    incoming: dict[str, int] = {}
    # a name defined in exactly one file: uses from other files count towards that file
    owners: dict[str, str | None] = {}
    for symbol in symbols.symbols:
        # functions and structs only: a short macro or global name is shared by accident
        if symbol.kind in ("function", "struct") and not symbol.is_static and "_" in symbol.name:
            owners[symbol.name] = symbol.path if owners.get(symbol.name, symbol.path) == symbol.path else None
    batch = []
    ref_count = 0
    for name, path, line, enclosing, kind in iter_refs(corpus.code, symbols):
        name_id = name_ids.setdefault(name, len(name_ids) + 1)
        name_counts[name] = name_counts.get(name, 0) + 1
        owner = owners.get(name)
        if owner and owner != path:
            incoming[owner] = incoming.get(owner, 0) + 1
        batch.append((name_id, file_rowid[path], line, symbol_rowid.get(enclosing) if enclosing else None, kind))
        if len(batch) >= 50000:
            connection.executemany("INSERT INTO symbol_refs_data VALUES (?,?,?,?,?)", batch)
            ref_count += len(batch)
            batch = []
    connection.executemany("INSERT INTO symbol_refs_data VALUES (?,?,?,?,?)", batch)
    ref_count += len(batch)
    connection.executemany(
        "INSERT INTO ref_names VALUES (?,?,?,?)",
        [(i, n, name_counts[n], round(math.log1p(name_counts[n]), 3)) for n, i in name_ids.items()],
    )
    connection.executemany(
        "UPDATE files SET centrality = ? WHERE path = ?",
        [(round(math.log1p(count), 3), path) for path, count in incoming.items()],
    )
    timer.step(f"indexed {ref_count} references")

    def count(table: str) -> int:
        return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    registry_counts = dict(connection.execute("SELECT type, COUNT(*) FROM registry_entries GROUP BY type").fetchall())
    record_counts = dict(connection.execute("SELECT dataset, COUNT(*) FROM doc_records GROUP BY dataset").fetchall())
    symbol_counts = dict(connection.execute("SELECT kind, COUNT(*) FROM symbols GROUP BY kind").fetchall())
    mention_total = count("doc_mentions")
    mention_resolved = connection.execute("SELECT COUNT(*) FROM doc_mentions WHERE target_id IS NOT NULL").fetchone()[0]
    stats = {
        "docs": count("docs"), "doc_sections": count("doc_sections"), "doc_mentions": mention_total,
        "doc_mentions_resolved": mention_resolved,
        "doc_mentions_stale": connection.execute("SELECT COUNT(*) FROM doc_mentions WHERE stale = 1").fetchone()[0],
        "doc_kernel_doc": count("doc_kernel_doc"), "doc_records": record_counts,
        "doc_records_matched_to_registry": dict(connection.execute(
            "SELECT dataset, COUNT(*) FROM doc_records WHERE registry_id IS NOT NULL GROUP BY dataset").fetchall()),
        "netlink_families": count("netlink_families"), "netlink_ops": count("netlink_ops"),
        "netlink_ops_with_handlers": connection.execute(
            "SELECT COUNT(*) FROM netlink_ops WHERE handler_symbol_ids != '[]'").fetchone()[0],
        "netlink_attrs": count("netlink_attrs"),
        "files": count("files"), "file_tags": count("file_tags"), "tag_aliases": count("tag_aliases"),
        "symbols": symbol_counts, "symbols_total": count("symbols"),
        "symbol_doc_links": count("symbol_doc_links"), "symbol_refs": ref_count,
        "registry_entries": registry_counts,
        "registry_unresolved": dict(connection.execute(
            "SELECT type, COUNT(*) FROM registry_entries WHERE resolved = 0 GROUP BY type").fetchall()),
        "registry_uses": count("registry_uses"), "registry_doc_links": count("registry_doc_links"),
        "parse_error_regions": symbol_stats["parse_error_regions"],
        "github_requests": client.requests,
    }
    meta = {
        "repo": GITHUB_REPO, "ref": GITHUB_REF,
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stats": json.dumps(stats, sort_keys=True),
    }
    connection.executemany("INSERT INTO meta VALUES (?,?)", list(meta.items()))
    connection.commit()
    connection.execute("INSERT INTO doc_sections_fts(doc_sections_fts) VALUES ('optimize')")
    connection.execute("INSERT INTO symbols_fts(symbols_fts) VALUES ('optimize')")
    connection.execute("INSERT INTO files_fts(files_fts) VALUES ('optimize')")
    connection.execute("INSERT INTO registry_fts(registry_fts) VALUES ('optimize')")
    connection.commit()
    connection.execute("VACUUM")
    connection.close()
    client.close()
    timer.step(f"done: {output} is {output.stat().st_size / 1e6:.1f} MB")
    return stats
