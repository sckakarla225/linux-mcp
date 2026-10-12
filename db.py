"""index.db: schema and connection helpers.

The index holds identifiers, line ranges, metadata, tags and links. It never holds source or
documentation text; that is fetched live from GitHub at the pinned ref.
"""

import json
import sqlite3
from pathlib import Path

INDEX_PATH = Path(__file__).resolve().parent / "index.db"
SCHEMA_VERSION = "2"

FTS_TOKENIZER = "porter unicode61"

SCHEMA = f"""
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);

-- Documentation ------------------------------------------------------------------------
CREATE TABLE docs (
    doc_path TEXT PRIMARY KEY,
    folder TEXT NOT NULL,
    format TEXT NOT NULL,
    title TEXT,
    line_count INTEGER,
    blob_sha TEXT,
    cluster TEXT
);
CREATE TABLE doc_sections (
    doc_id TEXT PRIMARY KEY,
    doc_path TEXT NOT NULL REFERENCES docs(doc_path),
    heading TEXT,
    level INTEGER,
    parent_doc_id TEXT,
    start_line INTEGER,
    end_line INTEGER
);
CREATE INDEX doc_sections_path ON doc_sections(doc_path, start_line);
CREATE INDEX doc_sections_parent ON doc_sections(parent_doc_id);
CREATE VIRTUAL TABLE doc_sections_fts USING fts5(
    heading, body, content='', tokenize='{FTS_TOKENIZER}'
);
CREATE TABLE doc_mentions (
    doc_id TEXT NOT NULL,
    line INTEGER,
    raw_text TEXT,
    mention_kind TEXT,
    target_type TEXT,
    target_id TEXT,
    method TEXT,
    confidence REAL,
    stale INTEGER
);
CREATE INDEX doc_mentions_doc ON doc_mentions(doc_id);
CREATE INDEX doc_mentions_target ON doc_mentions(target_type, target_id);
CREATE TABLE doc_kernel_doc (
    doc_id TEXT NOT NULL,
    source_path TEXT,
    mode TEXT,
    names TEXT
);
CREATE INDEX doc_kernel_doc_doc ON doc_kernel_doc(doc_id);
CREATE INDEX doc_kernel_doc_source ON doc_kernel_doc(source_path);
CREATE TABLE doc_records (
    record_id TEXT PRIMARY KEY,
    doc_id TEXT,
    line INTEGER,
    end_line INTEGER,
    dataset TEXT NOT NULL,
    key TEXT NOT NULL,
    attrs TEXT,
    registry_id TEXT
);
CREATE INDEX doc_records_dataset ON doc_records(dataset, key);
CREATE INDEX doc_records_doc ON doc_records(doc_id);
CREATE INDEX doc_records_registry ON doc_records(registry_id);

CREATE TABLE netlink_families (
    family TEXT PRIMARY KEY,
    spec_doc_id TEXT,
    protocol TEXT,
    uapi_header TEXT,
    generated_code TEXT,
    attrs TEXT
);
CREATE TABLE netlink_ops (
    family TEXT NOT NULL,
    op TEXT NOT NULL,
    value TEXT,
    doc_id TEXT,
    doc TEXT,
    do_request_attrs TEXT,
    do_reply_attrs TEXT,
    dump_attrs TEXT,
    registration_id TEXT,
    handler_symbol_ids TEXT,
    attrs TEXT,
    PRIMARY KEY (family, op)
);
CREATE TABLE netlink_attrs (
    family TEXT NOT NULL,
    attr_set TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT,
    doc_id TEXT,
    doc TEXT,
    attrs TEXT,
    PRIMARY KEY (family, attr_set, name)
);
CREATE INDEX netlink_attrs_name ON netlink_attrs(name);

-- Code ---------------------------------------------------------------------------------
CREATE TABLE files (
    path TEXT PRIMARY KEY,
    area TEXT,
    subsystem TEXT,
    file_type TEXT,
    line_count INTEGER,
    blob_sha TEXT,
    kconfig TEXT,
    maintainers TEXT,
    header_comment TEXT,
    -- log of how often other files use symbols defined here; ranks core files first in search
    centrality REAL NOT NULL DEFAULT 0
);
CREATE TABLE file_tags (
    path TEXT NOT NULL,
    tag TEXT NOT NULL,
    score REAL,
    source TEXT
);
CREATE INDEX file_tags_path ON file_tags(path);
CREATE INDEX file_tags_tag ON file_tags(tag);
CREATE TABLE tag_aliases (alias TEXT PRIMARY KEY, canonical_tag TEXT NOT NULL);
CREATE VIRTUAL TABLE files_fts USING fts5(
    path, tags, header_comment, tokenize='{FTS_TOKENIZER}'
);

-- Symbols ------------------------------------------------------------------------------
CREATE TABLE symbols (
    symbol_id TEXT PRIMARY KEY,
    path TEXT NOT NULL REFERENCES files(path),
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    start_line INTEGER,
    end_line INTEGER,
    signature TEXT,
    is_static INTEGER,
    is_exported INTEGER,
    is_macro_generated INTEGER,
    ifdef_guard TEXT,
    doc_comment TEXT
);
CREATE INDEX symbols_name ON symbols(name);
CREATE INDEX symbols_path ON symbols(path, start_line);
CREATE TABLE symbol_doc_links (
    symbol_id TEXT NOT NULL,
    doc_id TEXT NOT NULL,
    method TEXT,
    confidence REAL
);
CREATE INDEX symbol_doc_links_symbol ON symbol_doc_links(symbol_id);
CREATE INDEX symbol_doc_links_doc ON symbol_doc_links(doc_id);
CREATE VIRTUAL TABLE symbols_fts USING fts5(
    name, signature, doc_comment, content='', tokenize='{FTS_TOKENIZER}'
);

-- symbol_refs is stored with integer keys and exposed through a view.
CREATE TABLE ref_names (
    name_id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    ref_count INTEGER NOT NULL DEFAULT 0,
    ref_weight REAL NOT NULL DEFAULT 0  -- log(1 + ref_count)
);
CREATE TABLE symbol_refs_data (
    name_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    line INTEGER NOT NULL,
    enclosing_symbol INTEGER,
    ref_kind INTEGER NOT NULL
) ;
CREATE INDEX symbol_refs_name ON symbol_refs_data(name_id, file_id, line);
CREATE VIEW symbol_refs AS
    SELECT n.name AS name,
           f.path AS path,
           r.line AS line,
           s.symbol_id AS enclosing_symbol_id,
           CASE r.ref_kind WHEN 0 THEN 'call' WHEN 1 THEN 'address_of'
                           WHEN 2 THEN 'type_use' ELSE 'other' END AS ref_kind
    FROM symbol_refs_data r
    JOIN ref_names n ON n.name_id = r.name_id
    JOIN files f ON f.rowid = r.file_id
    LEFT JOIN symbols s ON s.rowid = r.enclosing_symbol;

-- Registries ---------------------------------------------------------------------------
CREATE TABLE registry_entries (
    entry_id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    key TEXT NOT NULL,
    symbol_id TEXT,
    path TEXT,
    line INTEGER,
    resolved INTEGER NOT NULL DEFAULT 1,
    attrs TEXT
);
CREATE INDEX registry_entries_type ON registry_entries(type, key);
CREATE INDEX registry_entries_symbol ON registry_entries(symbol_id);
CREATE INDEX registry_entries_path ON registry_entries(path);
CREATE TABLE registry_uses (
    entry_id TEXT NOT NULL,
    path TEXT,
    line INTEGER,
    symbol_id TEXT,
    use_kind TEXT
);
CREATE INDEX registry_uses_entry ON registry_uses(entry_id);
CREATE INDEX registry_uses_symbol ON registry_uses(symbol_id);
CREATE TABLE registry_doc_links (
    entry_id TEXT NOT NULL,
    doc_id TEXT NOT NULL,
    method TEXT,
    confidence REAL
);
CREATE INDEX registry_doc_links_entry ON registry_doc_links(entry_id);
CREATE INDEX registry_doc_links_doc ON registry_doc_links(doc_id);
-- Alternative keys for registry entries and doc records (a sysctl's bare name, a counter's
-- MIB constant, a netlink message constant, an ELF section name, ...).
CREATE TABLE lookup_aliases (type TEXT NOT NULL, alias TEXT NOT NULL, ref_id TEXT NOT NULL);
CREATE INDEX lookup_aliases_alias ON lookup_aliases(type, alias);
CREATE VIRTUAL TABLE registry_fts USING fts5(
    ref_id UNINDEXED, ref_type UNINDEXED, kind UNINDEXED, key, text,
    tokenize='{FTS_TOKENIZER}'
);
"""

REF_KINDS = {"call": 0, "address_of": 1, "type_use": 2, "other": 3}


class IndexMissing(RuntimeError):
    pass


def create(path: Path) -> sqlite3.Connection:
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(path)
    connection.executescript("PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;")
    connection.executescript(SCHEMA)
    connection.execute("INSERT INTO meta VALUES ('schema_version', ?)", (SCHEMA_VERSION,))
    return connection


def connect(path: Path = INDEX_PATH) -> sqlite3.Connection:
    """Open the index read-only."""
    if not path.is_file():
        raise IndexMissing(
            f"{path} does not exist; build it with `.venv/bin/python build_index.py` at the repo root"
        )
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def dumps(value) -> str | None:
    return None if value is None else json.dumps(value, separators=(",", ":"), sort_keys=True)


def loads(value):
    return None if value is None else json.loads(value)
