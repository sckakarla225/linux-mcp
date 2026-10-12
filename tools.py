"""Tool implementations: search, get_doc, get_file, get_symbol, query_registry, find_references.

The index (index.db) finds, outlines and links resources. Source and documentation text is
fetched live from GitHub at the pinned ref and cached in memory for the life of the process.
"""

import re
import threading

import db
import scope
from config import GITHUB_REF
from github import GitHubClient, GitHubError, git_blob_sha, permalink

MAX_LINES = 400
MAX_LINKS = 60
MAX_OUTLINE = 500
ENUM_CONTEXT_LINES = 6

SYMBOL_KINDS = ["function", "struct", "union", "enum", "macro", "global", "ops_instance", "typedef", "enum_constant"]
REGISTRY_TYPES = ["ops", "registration", "sysctl", "snmp", "tracepoint", "export", "kconfig", "bpf_helper"]
RECORD_TYPES = [
    "netlink", "netlink_attr", "net_cachelines", "xfrm_counter", "ethtool_msg", "operstate",
    "proc_net_tcp", "bpf_prog_type", "bpf_map_type", "kfunc_flag", "btf_kind", "bpf_isa",
]
# sysctl and snmp exist both as code registries and as doc records; the registry side leads.
DOC_ONLY_FALLBACK = {"sysctl": "sysctl", "snmp": "snmp"}
SEARCH_TYPES = ["doc", "file", "symbol", "registry", "record"]
REF_KINDS = ["call", "address_of", "type_use", "other"]

STOPWORDS = set(
    """a an and are as at be by can could do does for from how i if in into is it its of on or
    that the their then there these this to was what when where which who why will with would
    you your get gets got used use uses using happen happens work works chosen choose decided
    decide given about after before between during linux kernel""".split()
)

TOOL_FOR_TYPE = {"doc": "get_doc", "file": "get_file", "symbol": "get_symbol", "registry": "query_registry", "record": "query_registry"}


def _next(link_type: str, identifier: str) -> dict:
    if link_type == "doc":
        return {"tool": "get_doc", "args": {"doc_id": identifier}}
    if link_type == "file":
        return {"tool": "get_file", "args": {"path": identifier}}
    if link_type == "symbol":
        return {"tool": "get_symbol", "args": {"id_or_name": identifier}}
    kind, _, key = identifier.partition("/")
    return {"tool": "query_registry", "args": {"type": kind, "key": key}}


def make_link(link_type: str, identifier: str, relation: str, method: str | None = None,
              confidence: float | None = None, **extra) -> dict:
    link = {"type": link_type, "id": identifier, "relation": relation}
    if method is not None:
        link["method"] = method
    if confidence is not None:
        link["confidence"] = confidence
    link.update({k: v for k, v in extra.items() if v is not None})
    link["next"] = _next(link_type, identifier)
    return link


def error(message: str, next_step: dict | None = None, **extra) -> dict:
    result = {"error": message}
    result.update(extra)
    if next_step is not None:
        result["next"] = next_step
    return result


def _search_next(query: str, **args) -> dict:
    return {"tool": "search", "args": {"query": query, **args}}


def _cap_links(links: list[dict]) -> tuple[list[dict], int]:
    seen = set()
    unique = []
    for link in links:
        key = (link["type"], link.get("id"), link["relation"], link.get("raw_text"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(link)
    return unique[:MAX_LINKS], max(0, len(unique) - MAX_LINKS)


class Index:
    def __init__(self, path=db.INDEX_PATH, client: GitHubClient | None = None):
        self.connection = db.connect(path)
        self.lock = threading.Lock()
        self.client = client or GitHubClient()
        self.meta = dict(self.rows("SELECT key, value FROM meta"))
        self._verified: dict[str, bool] = {}
        self.alias_single: dict[str, str] = {}
        self.alias_phrases: list[tuple[str, str]] = []
        self.concept_aliases: dict[str, list[str]] = {}
        for alias, canonical in self.rows("SELECT alias, canonical_tag FROM tag_aliases"):
            if re.fullmatch(r"[a-z0-9_]+", alias):
                self.alias_single[alias] = canonical
            else:
                self.alias_phrases.append((alias, canonical))
            if alias != canonical:
                self.concept_aliases.setdefault(canonical, []).append(alias)

    # ---- database and fetch helpers ----

    def rows(self, sql: str, params: tuple = ()) -> list:
        with self.lock:
            return self.connection.execute(sql, params).fetchall()

    def row(self, sql: str, params: tuple = ()):
        with self.lock:
            return self.connection.execute(sql, params).fetchone()

    def fetch_lines(self, path: str, expected_sha: str | None) -> tuple[list[str], str | None]:
        """Lines of a file at the pinned ref, plus a warning if it differs from the index."""
        data = self.client.fetch_bytes(path)
        warning = None
        if expected_sha:
            if path not in self._verified:
                self._verified[path] = git_blob_sha(data) == expected_sha
            if not self._verified[path]:
                warning = f"{path} fetched from GitHub does not match the indexed blob; line ranges may be off. Rebuild index.db."
        lines = data.decode("utf-8", errors="replace").split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        return lines, warning

    # ---- shared lookups ----

    def symbol_link(self, symbol_id: str, relation: str, **extra) -> dict:
        return make_link("symbol", symbol_id, relation, **extra)

    def symbol_brief(self, row) -> dict:
        return {
            "id": row["symbol_id"], "name": row["name"], "kind": row["kind"], "path": row["path"],
            "start_line": row["start_line"], "end_line": row["end_line"],
            "signature": row["signature"], "is_static": bool(row["is_static"]),
            "ifdef_guard": row["ifdef_guard"],
            "permalink": permalink(row["path"], row["start_line"], row["end_line"]),
        }

    def doc_title(self, doc_id: str) -> str | None:
        row = self.row("SELECT heading FROM doc_sections WHERE doc_id = ?", (doc_id,))
        return row["heading"] if row else None

    # ==================================================================================
    # search
    # ==================================================================================

    def _query_terms(self, query: str) -> tuple[list[str], list[str], list[str]]:
        """(terms from the query, concept tags it touches, other spellings of those concepts)."""
        lowered = query.lower()
        tokens = re.findall(r"[A-Za-z0-9_]+", query)
        terms = [t for t in tokens if t.lower() not in STOPWORDS and (len(t) > 1 or t.isdigit())]
        if not terms:
            terms = tokens
        concepts = []
        for alias, canonical in self.alias_phrases:
            if re.search(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])", lowered) and canonical not in concepts:
                concepts.append(canonical)
        for token in tokens:
            canonical = self.alias_single.get(token.lower())
            if canonical and canonical not in concepts:
                concepts.append(canonical)
        present = {t.lower() for t in terms}
        spellings = []
        for concept in concepts:
            for alias in [concept] + self.concept_aliases.get(concept, []):
                if alias not in present and alias not in spellings:
                    spellings.append(alias)
        return terms, concepts, spellings[:12]

    @staticmethod
    def _match_expression(terms: list[str], operator: str) -> str:
        return f" {operator} ".join('"' + t.replace('"', "") + '"' for t in terms)

    def _fts(self, sql: str, terms: list[str], spellings: list[str], params: tuple, limit: int) -> list:
        """Run an FTS query and keep first-seen order.

        Short queries try every term first; longer ones, which read as questions, go straight
        to any-term matching and let bm25 favour the rarer words.
        """
        results = []
        seen = set()
        expressions = []
        if terms and len(terms) <= 3:
            expressions.append(self._match_expression(terms, "AND"))
        if len(terms) > 1 or spellings or not expressions:
            expressions.append(self._match_expression(terms + spellings, "OR"))
        for expression in expressions:
            if not expression:
                continue
            try:
                rows = self.rows(sql, (expression, *params, limit))
            except Exception:
                continue
            for row in rows:
                if row[0] not in seen:
                    seen.add(row[0])
                    results.append(row)
            if len(results) >= limit:
                break
        return results[:limit]

    def _symbol_hit(self, row) -> dict:
        return {
            "type": "symbol", "id": row["symbol_id"], "title": f"{row['name']} ({row['kind']})",
            "snippet": row["signature"],
            "permalink": permalink(row["path"], row["start_line"], row["end_line"]),
            "next": _next("symbol", row["symbol_id"]),
        }

    def _file_hit(self, row) -> dict:
        tags = [r["tag"] for r in self.rows("SELECT tag FROM file_tags WHERE path = ? ORDER BY score DESC LIMIT 8", (row["path"],))]
        header = (row["header_comment"] or "").split("\n")[0][:120]
        snippet = "tags: " + ", ".join(tags) if tags else ""
        if header:
            snippet = f"{header} | {snippet}" if snippet else header
        return {
            "type": "file", "id": row["path"], "title": row["path"], "snippet": snippet,
            "permalink": permalink(row["path"]), "next": _next("file", row["path"]),
        }

    def _doc_hit(self, row) -> dict:
        title = self.row("SELECT title, cluster FROM docs WHERE doc_path = ?", (row["doc_path"],))
        return {
            "type": "doc", "id": row["doc_id"], "title": row["heading"],
            "snippet": f"{title['title']} ({row['doc_path']}, {title['cluster']})",
            "permalink": permalink("Documentation/" + row["doc_path"], row["start_line"], row["end_line"]),
            "next": _next("doc", row["doc_id"]),
        }

    def _registry_hit(self, ref_id: str, ref_type: str) -> dict | None:
        kind, _, key = ref_id.partition("/")
        if ref_type == "registry":
            row = self.row("SELECT * FROM registry_entries WHERE entry_id = ?", (ref_id,))
            if row is None:
                return None
            return {
                "type": "registry", "id": ref_id, "title": f"{key} ({kind})",
                "snippet": self._entry_summary(row),
                "permalink": permalink(row["path"], row["line"]) if row["path"] else None,
                "next": _next("registry", ref_id),
            }
        if kind == "netlink":
            family, _, op = key.partition("/")
            row = self.row("SELECT * FROM netlink_ops WHERE family = ? AND op = ?", (family, op))
            if row is None:
                return None
            return {
                "type": "record", "id": ref_id, "title": f"{family} {op} (netlink operation)",
                "snippet": row["doc"] or "", "permalink": self._doc_permalink(row["doc_id"]),
                "next": _next("record", ref_id),
            }
        if kind == "netlink_attr":
            family, attr_set, name = (key.split("/", 2) + ["", ""])[:3]
            row = self.row("SELECT * FROM netlink_attrs WHERE family = ? AND attr_set = ? AND name = ?", (family, attr_set, name))
            if row is None:
                return None
            return {
                "type": "record", "id": ref_id, "title": f"{name} (netlink attribute, {family}/{attr_set})",
                "snippet": f"{row['type']}: {row['doc'] or ''}", "permalink": self._doc_permalink(row["doc_id"]),
                "next": _next("record", ref_id),
            }
        row = self.row("SELECT * FROM doc_records WHERE record_id = ?", (ref_id,))
        if row is None:
            return None
        return {
            "type": "record", "id": ref_id, "title": f"{row['key']} ({row['dataset']})",
            "snippet": self._record_summary(row), "permalink": self._record_permalink(row),
            "next": _next("record", ref_id),
        }

    def _doc_permalink(self, doc_id: str | None) -> str | None:
        if not doc_id:
            return None
        row = self.row("SELECT doc_path, start_line, end_line FROM doc_sections WHERE doc_id = ?", (doc_id,))
        if row is None:
            return None
        return permalink("Documentation/" + row["doc_path"], row["start_line"], row["end_line"])

    def _record_permalink(self, row) -> str | None:
        if not row["doc_id"]:
            return None
        doc_path = row["doc_id"].split("#", 1)[0]
        return permalink("Documentation/" + doc_path, row["line"], row["end_line"])

    def search(self, query: str, types=None, area=None, kind=None, limit: int = 20) -> dict:
        if not query or not query.strip():
            return error("query is empty; pass words or an identifier to search for")
        limit = max(1, min(int(limit or 20), 50))
        wanted = list(types) if types else list(SEARCH_TYPES)
        unknown = [t for t in wanted if t not in SEARCH_TYPES]
        if unknown:
            return error(f"unknown types {unknown}; use any of {SEARCH_TYPES}")
        symbol_kind = registry_kind = None
        if kind:
            if kind in SYMBOL_KINDS:
                symbol_kind, wanted = kind, [t for t in wanted if t == "symbol"] or ["symbol"]
            elif kind in REGISTRY_TYPES or kind in RECORD_TYPES:
                registry_kind = kind
                wanted = [t for t in wanted if t in ("registry", "record")] or ["registry", "record"]
            else:
                return error(f"unknown kind {kind!r}; symbol kinds: {SYMBOL_KINDS}; registry and record types: {REGISTRY_TYPES + RECORD_TYPES}")
        if area and scope.code_area(area.rstrip("/") + "/x") is None:
            return error(f"unknown area {area!r}; use one of {sorted(scope.AREAS)}")
        area_prefix = area.rstrip("/") + "/" if area else None
        if area_prefix:
            wanted = [t for t in wanted if t in ("file", "symbol")] or ["file", "symbol"]
        terms, concepts, spellings = self._query_terms(query)
        single = len(terms) == 1
        exact: list[dict] = []
        ranked: dict[str, list[dict]] = {t: [] for t in wanted}
        seen: set[tuple[str, str]] = set()

        def push(bucket: list[dict], hit: dict | None) -> None:
            if hit is not None and (hit["type"], hit["id"]) not in seen:
                seen.add((hit["type"], hit["id"]))
                bucket.append(hit)

        # exact identifier matches first
        for token in dict.fromkeys(re.findall(r"[A-Za-z_][A-Za-z0-9_.:/#@<>-]*", query)):
            # a plain word in a longer query is not an identifier lookup
            if not single and not re.search(r"[_./:]|[a-z][A-Z]|[A-Z]{3}", token):
                continue
            if "symbol" in wanted and len(token) >= 3:
                sql = "SELECT * FROM symbols WHERE name = ?"
                params: list = [token]
                if "::" in token:
                    sql, params = "SELECT * FROM symbols WHERE symbol_id = ?", [token]
                if symbol_kind:
                    sql += " AND kind = ?"
                    params.append(symbol_kind)
                if area_prefix:
                    sql += " AND path LIKE ?"
                    params.append(area_prefix + "%")
                sql += " ORDER BY is_static, kind = 'enum_constant', path LIMIT 6"
                for row in self.rows(sql, tuple(params)):
                    push(exact, self._symbol_hit(row))
            if "file" in wanted and "/" in token:
                row = self.row("SELECT * FROM files WHERE path = ?", (token,))
                if row is not None:
                    push(exact, self._file_hit(row))
            if "doc" in wanted and "/" in token:
                row = self.row("SELECT * FROM doc_sections WHERE doc_id = ? OR (doc_path = ? AND level = 0)", (token, token))
                if row is not None:
                    push(exact, self._doc_hit(row))
            if ("registry" in wanted or "record" in wanted) and len(token) >= 3:
                sql = "SELECT type, ref_id FROM lookup_aliases WHERE alias = ?"
                params = [token]
                if registry_kind:
                    sql += " AND type = ?"
                    params.append(registry_kind)
                found = self.rows(sql + " LIMIT 8", tuple(params))
                direct = self.rows(
                    "SELECT type, entry_id AS ref_id FROM registry_entries WHERE key = ?"
                    + (" AND type = ?" if registry_kind else "") + " LIMIT 4",
                    (token, registry_kind) if registry_kind else (token,),
                )
                records = self.rows(
                    "SELECT dataset AS type, record_id AS ref_id FROM doc_records WHERE key = ?"
                    + (" AND dataset = ?" if registry_kind else "") + " LIMIT 4",
                    (token, registry_kind) if registry_kind else (token,),
                )
                for row in list(direct) + list(records) + list(found):
                    if row["type"] == "export":
                        continue
                    ref_type = "registry" if row["type"] in REGISTRY_TYPES and self.row(
                        "SELECT 1 FROM registry_entries WHERE entry_id = ?", (row["ref_id"],)) else "record"
                    if ref_type in wanted:
                        push(exact, self._registry_hit(row["ref_id"], ref_type))

        per_type = limit
        if "symbol" in wanted:
            sql = (
                "SELECT s.rowid AS rid, s.* FROM symbols_fts f JOIN symbols s ON s.rowid = f.rowid "
                "LEFT JOIN ref_names n ON n.name = s.name WHERE symbols_fts MATCH ?"
            )
            params = []
            if symbol_kind:
                sql += " AND s.kind = ?"
                params.append(symbol_kind)
            else:
                sql += " AND s.kind != 'enum_constant'"
            if area_prefix:
                sql += " AND s.path LIKE ?"
                params.append(area_prefix + "%")
            # bm25 is negative; widely used names get a stronger (more negative) score
            sql += (
                " ORDER BY bm25(symbols_fts, 10.0, 3.0, 1.0) * (1.0 + 0.12 * ifnull(n.ref_weight, 0)),"
                " s.is_static, length(s.name) LIMIT ?"
            )
            for row in self._fts(sql, terms, spellings, tuple(params), per_type):
                push(ranked["symbol"], self._symbol_hit(row))
        if "file" in wanted:
            # Keyword tags first: sum the TF-IDF scores of the tags a query touches, prefer
            # files that match more of them, and let widely used files lead.
            tag_terms = list(dict.fromkeys([t.lower() for t in terms] + concepts + [s for s in spellings if " " not in s]))
            if tag_terms:
                placeholders = ",".join("?" * len(tag_terms))
                sql = (
                    f"SELECT x.* FROM (SELECT path, SUM(score) AS total, COUNT(DISTINCT tag) AS matched "
                    f"FROM file_tags WHERE tag IN ({placeholders}) GROUP BY path) t JOIN files x ON x.path = t.path"
                )
                params = list(tag_terms)
                if area_prefix:
                    sql += " WHERE x.path LIKE ?"
                    params.append(area_prefix + "%")
                sql += " ORDER BY t.matched * t.matched * t.total * (1.0 + 0.15 * x.centrality) DESC LIMIT ?"
                for row in self.rows(sql, (*params, per_type)):
                    push(ranked["file"], self._file_hit(row))
            sql = "SELECT f.rowid AS rid, x.* FROM files_fts f JOIN files x ON x.rowid = f.rowid WHERE files_fts MATCH ?"
            params = []
            if area_prefix:
                sql += " AND x.path LIKE ?"
                params.append(area_prefix + "%")
            sql += " ORDER BY bm25(files_fts, 4.0, 6.0, 1.0) * (1.0 + 0.12 * x.centrality) LIMIT ?"
            for row in self._fts(sql, terms, spellings, tuple(params), per_type):
                push(ranked["file"], self._file_hit(row))
        if "doc" in wanted:
            sql = (
                "SELECT f.rowid AS rid, d.* FROM doc_sections_fts f JOIN doc_sections d ON d.rowid = f.rowid "
                "WHERE doc_sections_fts MATCH ? ORDER BY bm25(doc_sections_fts, 6.0, 1.0) LIMIT ?"
            )
            for row in self._fts(sql, terms, spellings, (), per_type):
                push(ranked["doc"], self._doc_hit(row))
        if "registry" in wanted or "record" in wanted:
            sql = "SELECT ref_id, ref_type, kind FROM registry_fts WHERE registry_fts MATCH ?"
            params = []
            if registry_kind:
                sql += " AND kind = ?"
                params.append(registry_kind)
            sql += " ORDER BY bm25(registry_fts, 0.0, 0.0, 0.0, 3.0, 1.0) LIMIT ?"
            for row in self._fts(sql, terms, spellings, tuple(params), per_type * 2):
                if row["ref_type"] in wanted:
                    push(ranked[row["ref_type"]], self._registry_hit(row["ref_id"], row["ref_type"]))

        # identifier-like queries lead with symbols and registries; questions lead with docs
        identifier_like = single or any("_" in t for t in terms) or (len(terms) <= 2 and any(t.isupper() and len(t) > 2 for t in terms))
        order = ["symbol", "registry", "record", "doc", "file"] if identifier_like else ["doc", "file", "symbol", "registry", "record"]
        hits = exact[:limit]
        position = 0
        while len(hits) < limit and any(position < len(ranked.get(t, [])) for t in order):
            for hit_type in order:
                bucket = ranked.get(hit_type, [])
                if position < len(bucket) and len(hits) < limit:
                    hits.append(bucket[position])
            position += 1
        result = {"query": query, "count": len(hits), "hits": hits}
        if concepts:
            result["expanded_concepts"] = concepts
        if not hits:
            result["hint"] = (
                f"nothing in the {GITHUB_REF} networking index matched; try fewer or different words, "
                "an identifier, or drop the types/area/kind filters"
            )
        return result

    # ==================================================================================
    # get_doc
    # ==================================================================================

    def _mention_links(self, doc_ids: list[str]) -> list[dict]:
        links = []
        placeholders = ",".join("?" * len(doc_ids))
        rows = self.rows(
            f"SELECT * FROM doc_mentions WHERE doc_id IN ({placeholders}) ORDER BY line", tuple(doc_ids)
        )
        for row in rows:
            if row["target_id"] is None:
                links.append({
                    "type": "unresolved", "raw_text": row["raw_text"], "mention_kind": row["mention_kind"],
                    "relation": "mentions", "line": row["line"], "stale": bool(row["stale"]),
                    "next": _search_next(row["raw_text"].rstrip("()").replace("struct ", "")),
                })
                continue
            target_type = row["target_type"]
            if target_type == "file" and self.row("SELECT 1 FROM files WHERE path = ?", (row["target_id"],)) is None:
                links.append({
                    "type": "unresolved", "raw_text": row["raw_text"], "mention_kind": "path",
                    "relation": "mentions", "line": row["line"], "stale": bool(row["stale"]),
                    "note": "exists at this tag but is outside the v1 networking scope"
                            + ("; the path written in the doc no longer exists" if row["stale"] else ""),
                    "permalink": permalink(row["target_id"]),
                })
                continue
            links.append(make_link(
                target_type, row["target_id"], "mentions", row["method"], row["confidence"],
                raw_text=row["raw_text"], line=row["line"], stale=True if row["stale"] else None,
            ))
        for row in self.rows(
            f"SELECT * FROM doc_kernel_doc WHERE doc_id IN ({placeholders})", tuple(doc_ids)
        ):
            in_scope = self.row("SELECT 1 FROM files WHERE path = ?", (row["source_path"],)) is not None
            if in_scope:
                links.append(make_link("file", row["source_path"], "kernel_doc", "kernel_doc_directive", 1.0,
                                       mode=row["mode"], names=row["names"] or None))
        return links

    def _records_in(self, doc_id: str, start: int, end: int) -> list[dict]:
        doc_path = doc_id.split("#", 1)[0]
        rows = self.rows(
            "SELECT record_id, dataset, key, line FROM doc_records WHERE doc_id LIKE ? AND line BETWEEN ? AND ? ORDER BY line",
            (doc_path + "#%", start, end),
        )
        return [
            {"id": r["record_id"], "dataset": r["dataset"], "key": r["key"], "line": r["line"],
             "next": _next("record", r["record_id"])}
            for r in rows
        ]

    def get_doc(self, doc_id: str) -> dict:
        doc_id = (doc_id or "").strip()
        if doc_id.startswith("Documentation/"):
            doc_id = doc_id[len("Documentation/"):]
        window = None
        match = re.search(r"@L(\d+)-L(\d+)$", doc_id)
        if match:
            window = (int(match.group(1)), int(match.group(2)))
            doc_id = doc_id[: match.start()]
        doc_path = doc_id.split("#", 1)[0]
        doc = self.row("SELECT * FROM docs WHERE doc_path = ?", (doc_path,))
        if doc is None:
            folder = doc_path.split("/", 1)[0]
            if folder not in scope.DOC_FOLDERS:
                return error(
                    f"{doc_path} is not in the {GITHUB_REF} index: only Documentation/{{{', '.join(scope.DOC_FOLDERS)}}} are covered",
                    _search_next(doc_path.rsplit("/", 1)[-1].rsplit(".", 1)[0], types=["doc"]),
                )
            return error(
                f"{doc_path} is not in the {GITHUB_REF} index (not found, or excluded from the v1 networking scope); try `search`",
                _search_next(doc_path.rsplit("/", 1)[-1].rsplit(".", 1)[0], types=["doc"]),
            )
        full_path = "Documentation/" + doc_path
        if "#" not in doc_id and window is None:
            sections = self.rows(
                "SELECT doc_id, heading, level, start_line, end_line FROM doc_sections WHERE doc_path = ? ORDER BY start_line, level",
                (doc_path,),
            )
            datasets = self.rows(
                "SELECT dataset, COUNT(*) AS n FROM doc_records WHERE doc_id LIKE ? GROUP BY dataset", (doc_path + "#%",)
            )
            links = self._mention_links([s["doc_id"] for s in sections[:300]]) if len(sections) <= 300 else []
            files_only = [l for l in links if l["type"] == "file"]
            capped, more = _cap_links(files_only)
            result = {
                "doc_path": doc_path, "title": doc["title"], "folder": doc["folder"], "format": doc["format"],
                "cluster": doc["cluster"], "line_count": doc["line_count"], "permalink": permalink(full_path),
                "section_count": len(sections),
                "sections": [
                    {"doc_id": s["doc_id"], "heading": s["heading"], "level": s["level"],
                     "start_line": s["start_line"], "end_line": s["end_line"]}
                    for s in sections[:MAX_OUTLINE]
                ],
                "records": [
                    {"dataset": d["dataset"], "count": d["n"],
                     "next": {"tool": "query_registry", "args": {"type": d["dataset"]}}}
                    for d in datasets
                ],
                "links": capped,
            }
            if len(sections) > MAX_OUTLINE:
                result["sections_truncated"] = len(sections) - MAX_OUTLINE
            if more:
                result["links_truncated"] = more
            result["hint"] = "open a section with get_doc(doc_id); links here list only the code files this doc points to"
            return result

        if "#" in doc_id:
            section = self.row("SELECT * FROM doc_sections WHERE doc_id = ?", (doc_id,))
            if section is None:
                slug = doc_id.split("#", 1)[1]
                near = self.rows(
                    "SELECT doc_id, heading FROM doc_sections WHERE doc_path = ? AND doc_id LIKE ? LIMIT 8",
                    (doc_path, f"%{slug.split('-')[0]}%"),
                )
                return error(
                    f"section {doc_id!r} not found in the {GITHUB_REF} index; call get_doc with the doc path to list its sections",
                    {"tool": "get_doc", "args": {"doc_id": doc_path}},
                    similar_sections=[{"doc_id": r["doc_id"], "heading": r["heading"]} for r in near],
                )
        else:
            section = self.row("SELECT * FROM doc_sections WHERE doc_path = ? ORDER BY level, start_line LIMIT 1", (doc_path,))
        children = self.rows(
            "SELECT doc_id, heading, start_line, end_line FROM doc_sections WHERE parent_doc_id = ? ORDER BY start_line",
            (section["doc_id"],),
        )
        start, end = section["start_line"], section["end_line"]
        try:
            lines, warning = self.fetch_lines(full_path, doc["blob_sha"])
        except GitHubError as exc:
            return error(f"could not fetch {full_path} from GitHub: {exc}", permalink=permalink(full_path, start, end))
        end = min(end, len(lines))
        truncated = None
        if window is not None:
            text_start = max(start, window[0])
            text_end = min(end, window[1], text_start + MAX_LINES - 1)
        elif end - start + 1 <= MAX_LINES:
            text_start, text_end = start, end
        else:
            # too long to return whole: give the section's own text, up to its first subsection
            own_end = children[0]["start_line"] - 1 if children else end
            text_start, text_end = start, min(max(own_end, start), start + MAX_LINES - 1)
        if text_end < end:
            next_end = min(end, text_end + MAX_LINES)
            truncated = {
                "shown": [text_start, text_end], "section": [start, end],
                "reason": f"sections are returned at most {MAX_LINES} lines at a time",
                "next": {"tool": "get_doc", "args": {"doc_id": f"{section['doc_id']}@L{text_end + 1}-L{next_end}"}},
            }
            if children:
                truncated["hint"] = "or open one of the child sections listed in `children`"
        subtree = [section["doc_id"]] + [
            r["doc_id"] for r in self.rows(
                "SELECT doc_id FROM doc_sections WHERE doc_path = ? AND start_line >= ? AND end_line <= ? AND doc_id != ?",
                (doc_path, text_start, max(text_end, text_start), section["doc_id"]),
            )
        ]
        links = [l for l in self._mention_links(subtree[:200]) if "line" not in l or text_start <= l["line"] <= text_end]
        if section["parent_doc_id"]:
            links.insert(0, make_link("doc", section["parent_doc_id"], "contained_in", heading=self.doc_title(section["parent_doc_id"])))
        for child in children:
            links.append(make_link("doc", child["doc_id"], "contains", heading=child["heading"]))
        for row in self.rows("SELECT * FROM registry_doc_links WHERE doc_id = ? ORDER BY confidence DESC LIMIT 40", (section["doc_id"],)):
            links.append(make_link("registry", row["entry_id"], "documents", row["method"], row["confidence"]))
        if doc["format"] == "yaml" and "#op/" in section["doc_id"]:
            family = doc_path.rsplit("/", 1)[-1][: -len(".yaml")]
            links.append(make_link("record", f"netlink/{family}/{section['doc_id'].split('#op/', 1)[1]}", "describes", "netlink_spec", 1.0))
        records = self._records_in(section["doc_id"], text_start, text_end)
        capped, more = _cap_links(links)
        result = {
            "doc_id": section["doc_id"], "doc_path": doc_path, "title": doc["title"],
            "heading": section["heading"], "level": section["level"], "cluster": doc["cluster"],
            "start_line": start, "end_line": end,
            "permalink": permalink(full_path, text_start, text_end),
            "text_lines": [text_start, text_end],
            "text": "\n".join(lines[text_start - 1 : text_end]),
            "parent": section["parent_doc_id"],
            "children": [
                {"doc_id": c["doc_id"], "heading": c["heading"], "start_line": c["start_line"], "end_line": c["end_line"]}
                for c in children
            ],
            "links": capped,
        }
        if records:
            result["records"] = records[:40]
            if len(records) > 40:
                result["records_truncated"] = len(records) - 40
        if truncated:
            result["truncated"] = truncated
        if more:
            result["links_truncated"] = more
        if warning:
            result["warning"] = warning
        return result

    # ==================================================================================
    # get_file
    # ==================================================================================

    def get_file(self, path: str, start_line: int | None = None, end_line: int | None = None) -> dict:
        path = (path or "").strip().lstrip("/")
        row = self.row("SELECT * FROM files WHERE path = ?", (path,))
        if row is None:
            if path.startswith("Documentation/"):
                return error(
                    f"{path} is documentation; read it with get_doc",
                    {"tool": "get_doc", "args": {"doc_id": path[len("Documentation/"):]}},
                )
            if scope.code_area(path) is None or not scope.code_in_scope(path):
                return error(
                    scope.out_of_scope_reason(path) + f"; it may still exist at {GITHUB_REF}",
                    _search_next(path.rsplit("/", 1)[-1].rsplit(".", 1)[0]), permalink=permalink(path),
                )
            return error(
                f"{path} not found in the {GITHUB_REF} index; try `search`",
                _search_next(path.rsplit("/", 1)[-1].rsplit(".", 1)[0], types=["file"]),
            )
        reading = start_line is not None or end_line is not None
        if reading:
            first = max(1, int(start_line or 1))
            last = int(end_line) if end_line is not None else first + MAX_LINES - 1
            if last < first:
                return error(f"end_line ({last}) is before start_line ({first})")
            if first > row["line_count"]:
                return error(f"{path} has {row['line_count']} lines; start_line {first} is past the end")
            requested_last = min(last, row["line_count"])
            last = min(requested_last, first + MAX_LINES - 1)
        tags = [
            {"tag": r["tag"], "score": r["score"], "source": r["source"]}
            for r in self.rows("SELECT tag, score, source FROM file_tags WHERE path = ? ORDER BY score DESC", (path,))
        ]
        result = {
            "path": path, "area": row["area"], "subsystem": row["subsystem"], "file_type": row["file_type"],
            "line_count": row["line_count"], "kconfig": row["kconfig"],
            "maintainers": db.loads(row["maintainers"]) or [],
            "tags": [t["tag"] for t in tags], "header_comment": row["header_comment"],
            "permalink": permalink(path),
        }
        sql = "SELECT symbol_id, name, kind, start_line, end_line FROM symbols WHERE path = ? AND kind != 'enum_constant'"
        params: list = [path]
        if reading:
            sql += " AND end_line >= ? AND start_line <= ?"
            params += [first, last]
        symbols = self.rows(sql + " ORDER BY start_line", tuple(params))
        counts = dict(self.rows("SELECT kind, COUNT(*) FROM symbols WHERE path = ? GROUP BY kind", (path,)))
        # one compact row per symbol keeps the outline of a 500-symbol file readable
        outline = []
        for symbol in symbols[:MAX_OUTLINE]:
            entry = [symbol["name"], symbol["kind"], symbol["start_line"], symbol["end_line"]]
            if symbol["symbol_id"] != f"{path}::{symbol['name']}":
                entry.append(symbol["symbol_id"])
            outline.append(entry)
        result["symbol_counts"] = counts
        result["symbol_columns"] = ["name", "kind", "start_line", "end_line", "id (only when it is not <path>::<name>)"]
        result["symbols"] = outline
        if len(symbols) > MAX_OUTLINE:
            result["symbols_truncated"] = {
                "omitted": len(symbols) - MAX_OUTLINE,
                "hint": "read a line range to list the symbols in it, or use search with this file's area",
            }
        links: list[dict] = []
        if row["kconfig"]:
            links.append(make_link("registry", f"kconfig/{row['kconfig']}", "built_by", "makefile", 1.0))
        for doc_row in self.rows(
            "SELECT DISTINCT doc_id, method, confidence FROM doc_mentions WHERE target_type = 'file' AND target_id = ? LIMIT 20", (path,)
        ):
            links.append(make_link("doc", doc_row["doc_id"], "documented_by", doc_row["method"], doc_row["confidence"], heading=self.doc_title(doc_row["doc_id"])))
        for doc_row in self.rows("SELECT DISTINCT doc_id, mode FROM doc_kernel_doc WHERE source_path = ? LIMIT 10", (path,)):
            links.append(make_link("doc", doc_row["doc_id"], "documented_by", "kernel_doc_directive", 1.0, heading=self.doc_title(doc_row["doc_id"])))
        for doc_row in self.rows(
            "SELECT l.doc_id, COUNT(*) AS n, MAX(l.confidence) AS confidence FROM symbol_doc_links l JOIN symbols s ON s.symbol_id = l.symbol_id "
            "WHERE s.path = ? GROUP BY l.doc_id ORDER BY n DESC, confidence DESC LIMIT 12", (path,)
        ):
            links.append(make_link("doc", doc_row["doc_id"], "documented_by", "symbol_mentions", doc_row["confidence"],
                                   symbols_mentioned=doc_row["n"], heading=self.doc_title(doc_row["doc_id"])))
        registry_counts = dict(self.rows("SELECT type, COUNT(*) FROM registry_entries WHERE path = ? GROUP BY type", (path,)))
        if registry_counts:
            result["registry_counts"] = registry_counts
        sql = "SELECT entry_id, type, line FROM registry_entries WHERE path = ? AND type != 'export'"
        params = [path]
        if reading:
            sql += " AND line BETWEEN ? AND ?"
            params += [first, last]
        sql += " ORDER BY CASE type WHEN 'registration' THEN 0 WHEN 'sysctl' THEN 1 WHEN 'snmp' THEN 2 WHEN 'tracepoint' THEN 3 WHEN 'kconfig' THEN 4 WHEN 'bpf_helper' THEN 5 ELSE 6 END, line LIMIT 40"
        for entry in self.rows(sql, tuple(params)):
            links.append(make_link("registry", entry["entry_id"], "contains", line=entry["line"]))
        if reading:
            try:
                lines, warning = self.fetch_lines(path, row["blob_sha"])
            except GitHubError as exc:
                return error(f"could not fetch {path} from GitHub: {exc}", permalink=permalink(path, first, last))
            last = min(last, len(lines))
            result["start_line"], result["end_line"] = first, last
            result["permalink"] = permalink(path, first, last)
            result["source"] = "\n".join(lines[first - 1 : last])
            if last < requested_last:
                result["truncated"] = {
                    "reason": f"at most {MAX_LINES} lines per call",
                    "next": {"tool": "get_file", "args": {"path": path, "start_line": last + 1,
                                                          "end_line": min(requested_last, last + MAX_LINES)}},
                }
            if warning:
                result["warning"] = warning
        capped, more = _cap_links(links)
        result["links"] = capped
        if more:
            result["links_truncated"] = more
        return result

    # ==================================================================================
    # get_symbol
    # ==================================================================================

    def _symbol_links(self, symbol) -> list[dict]:
        symbol_id = symbol["symbol_id"]
        links = [make_link("file", symbol["path"], "defined_in")]
        for row in self.rows(
            "SELECT doc_id, method, confidence FROM symbol_doc_links WHERE symbol_id = ? ORDER BY confidence DESC LIMIT 12", (symbol_id,)
        ):
            links.append(make_link("doc", row["doc_id"], "documented_by", row["method"], row["confidence"], heading=self.doc_title(row["doc_id"])))
        defined: set[str] = set()
        for row in self.rows("SELECT entry_id, type FROM registry_entries WHERE symbol_id = ? LIMIT 25", (symbol_id,)):
            relation = {"ops": "defines", "export": "exported_as", "sysctl": "contains", "snmp": "contains",
                        "bpf_helper": "implements", "registration": "handles"}.get(row["type"], "defines")
            defined.add(row["entry_id"])
            links.append(make_link("registry", row["entry_id"], relation))
        seen_member: set[tuple[str, str]] = set()
        for row in self.rows(
            "SELECT entry_id, use_kind, path, line FROM registry_uses WHERE symbol_id = ? ORDER BY use_kind LIMIT 80", (symbol_id,)
        ):
            use_kind = row["use_kind"]
            if use_kind.startswith("member:"):
                key = (row["entry_id"], use_kind)
                if key in seen_member:
                    continue
                seen_member.add(key)
                links.append(make_link("registry", row["entry_id"], "member_of", member=use_kind.split(":", 1)[1]))
            elif use_kind.startswith("handler:"):
                role = use_kind.split(":", 1)[1]
                if role == "impl" and row["entry_id"] in defined:
                    continue
                relation = {"doit": "doit_handler", "dumpit": "dumpit_handler"}.get(role, f"{role}_handler")
                links = [l for l in links if not (l["id"] == row["entry_id"] and l["relation"] == "handles")]
                links.append(make_link("registry", row["entry_id"], relation))
            else:
                links.append(make_link("registry", row["entry_id"], "uses", use_kind=use_kind, line=row["line"]))
        if symbol["kind"] in ("enum_constant", "macro"):
            # a constant that names a registry entry or record (a message type, a MIB id...)
            for row in self.rows(
                "SELECT DISTINCT type, ref_id FROM lookup_aliases WHERE alias = ? AND type != 'export' LIMIT 10", (symbol["name"],)
            ):
                is_entry = self.row("SELECT 1 FROM registry_entries WHERE entry_id = ?", (row["ref_id"],)) is not None
                links.append(make_link("registry" if is_entry else "record", row["ref_id"], "identifies", "name_match", 0.9))
        if symbol["kind"] == "enum_constant":
            parent = re.match(r"enum (\w+) ::", symbol["signature"] or "")
            if parent:
                enum_row = self.row("SELECT symbol_id FROM symbols WHERE path = ? AND name = ? AND kind = 'enum'", (symbol["path"], parent.group(1)))
                if enum_row:
                    links.append(make_link("symbol", enum_row["symbol_id"], "member_of"))
        count = self.row(
            "SELECT COUNT(*) AS n FROM symbol_refs_data r JOIN ref_names n ON n.name_id = r.name_id WHERE n.name = ?", (symbol["name"],)
        )["n"]
        links.append({
            "type": "references", "id": symbol["name"], "relation": "used_at", "count": count,
            "next": {"tool": "find_references", "args": {"name": symbol["name"]}},
        })
        return links

    def get_symbol(self, id_or_name: str) -> dict:
        wanted = (id_or_name or "").strip()
        if not wanted:
            return error("id_or_name is empty; pass a symbol id (path::name) or a bare name")
        if "::" in wanted:
            rows = self.rows("SELECT * FROM symbols WHERE symbol_id = ?", (wanted,))
            if not rows:
                path, _, name = wanted.partition("::")
                name = name.split("@", 1)[0]
                rows = self.rows("SELECT * FROM symbols WHERE path = ? AND name = ? ORDER BY start_line", (path, name))
                if not rows and self.row("SELECT 1 FROM files WHERE path = ?", (path,)) is None:
                    reason = scope.out_of_scope_reason(path) if not scope.code_in_scope(path) else f"{path} is not in the {GITHUB_REF} index"
                    return error(f"{reason}; try `search`", _search_next(name, types=["symbol"]))
                if not rows:
                    elsewhere = self.rows("SELECT * FROM symbols WHERE name = ? ORDER BY is_static, path LIMIT 10", (name,))
                    return error(
                        f"{name} is not defined in {path} in the {GITHUB_REF} index; try `search`",
                        _search_next(name, types=["symbol"]),
                        defined_elsewhere=[self.symbol_brief(r) for r in elsewhere],
                    )
        else:
            rows = self.rows(
                "SELECT * FROM symbols WHERE name = ? ORDER BY kind = 'enum_constant', is_static, path, start_line", (wanted,)
            )
            if not rows:
                return error(
                    f"{wanted} not found in the {GITHUB_REF} index (it may be outside the v1 networking scope); try `search`",
                    _search_next(wanted),
                )
        if len(rows) > 1:
            return {
                "name": rows[0]["name"], "ambiguous": True, "count": len(rows),
                "message": "several definitions; call get_symbol again with one of these ids",
                "candidates": [
                    dict(self.symbol_brief(r), next=_next("symbol", r["symbol_id"])) for r in rows[:40]
                ],
            }
        symbol = rows[0]
        file_row = self.row("SELECT blob_sha FROM files WHERE path = ?", (symbol["path"],))
        start, end = symbol["start_line"], symbol["end_line"]
        shown_end = min(end, start + MAX_LINES - 1)
        try:
            lines, warning = self.fetch_lines(symbol["path"], file_row["blob_sha"] if file_row else None)
        except GitHubError as exc:
            return error(f"could not fetch {symbol['path']} from GitHub: {exc}", permalink=permalink(symbol["path"], start, end))
        source_start = start
        if symbol["kind"] == "enum_constant":
            # one line says little: show the neighbouring constants of the enum too
            source_start = max(1, start - ENUM_CONTEXT_LINES)
            shown_end = min(len(lines), end + ENUM_CONTEXT_LINES)
        result = {
            "id": symbol["symbol_id"], "name": symbol["name"], "kind": symbol["kind"], "path": symbol["path"],
            "start_line": start, "end_line": end, "signature": symbol["signature"],
            "is_static": bool(symbol["is_static"]), "is_exported": bool(symbol["is_exported"]),
            "is_macro_generated": bool(symbol["is_macro_generated"]), "ifdef_guard": symbol["ifdef_guard"],
            "has_kernel_doc": bool(symbol["doc_comment"]),
            "permalink": permalink(symbol["path"], start, end),
            "source": "\n".join(lines[source_start - 1 : shown_end]),
        }
        if symbol["kind"] == "enum_constant":
            result["source_lines"] = [source_start, shown_end]
        if shown_end < end:
            result["truncated"] = {
                "shown": [start, shown_end], "reason": f"at most {MAX_LINES} lines per call",
                "next": {"tool": "get_file", "args": {"path": symbol["path"], "start_line": shown_end + 1,
                                                      "end_line": min(end, shown_end + MAX_LINES)}},
            }
        capped, more = _cap_links(self._symbol_links(symbol))
        result["links"] = capped
        if more:
            result["links_truncated"] = more
        if warning:
            result["warning"] = warning
        return result

    # ==================================================================================
    # query_registry
    # ==================================================================================

    def _entry_summary(self, row) -> str:
        attrs = db.loads(row["attrs"]) or {}
        kind = row["type"]
        if kind == "ops":
            members = attrs.get("members") or {}
            extra = f", {attrs.get('elements')} elements" if attrs.get("is_array") else f", {len(members)} function members"
            return f"struct {attrs.get('struct_type')} instance in {row['path']}{extra}"
        if kind == "registration":
            mechanism = attrs.get("mechanism")
            if mechanism == "rtnl":
                handlers = ", ".join(f"{r}={str(attrs[r]).split('::')[-1]}" for r in ("doit", "dumpit") if attrs.get(r))
                return f"rtnetlink {attrs.get('msg_type')} for {attrs.get('family')}: {handlers}"
            if mechanism == "genl":
                return f"generic netlink family {attrs.get('family')!r} ({attrs.get('command_count', 0)} commands) registered in {row['path']}"
            if mechanism == "nfnl":
                return f"nfnetlink {attrs.get('msg_type')} handled by {str(attrs.get('call')).split('::')[-1]}"
            if mechanism == "netfilter":
                return f"netfilter hook {str(attrs.get('hook')).split('::')[-1]} at {attrs.get('protocol')} {attrs.get('hooknum')}, priority {attrs.get('priority')}"
            if mechanism == "pernet":
                return f"pernet {attrs.get('kind')} operations {attrs.get('ops')} in {row['path']}"
            return f"{attrs.get('level')}({attrs.get('function')}) in {row['path']}"
        if kind == "sysctl":
            handler = str(attrs.get("proc_handler") or attrs.get("macro") or "").split("::")[-1]
            return f"/proc/sys/{row['key'].replace('.', '/')} (table {str(attrs.get('table')).split('::')[-1]}, handler {handler})"
        if kind == "snmp":
            return f"{attrs.get('mib')} in {attrs.get('mib_table')}, shown in {attrs.get('proc_file')}"
        if kind == "tracepoint":
            return f"trace event {attrs.get('system')}:{row['key']}" + (f" (class {attrs['class']})" if attrs.get("class") else "")
        if kind == "export":
            return f"exported ({attrs.get('license')}) from {row['path']}"
        if kind == "kconfig":
            return f"{attrs.get('value_type') or 'option'}: {attrs.get('prompt') or (attrs.get('help') or '')[:80] or attrs.get('note', '')}"
        if kind == "bpf_helper":
            return attrs.get("signature") or ""
        return ""

    def _record_summary(self, row) -> str:
        attrs = db.loads(row["attrs"]) or {}
        dataset = row["dataset"]
        if dataset == "sysctl":
            return f"{attrs.get('value_type')}: {(attrs.get('description') or '')[:140]}"
        if dataset == "net_cachelines":
            return f"{attrs.get('type')} {attrs.get('struct')}.{attrs.get('field')}: tx {attrs.get('fastpath_tx_access')}, rx {attrs.get('fastpath_rx_access')}"
        if dataset == "bpf_prog_type":
            return f"{attrs.get('program_type')} attach {attrs.get('attach_type')} SEC(\"{attrs.get('elf_section')}\")"
        if dataset == "bpf_isa":
            return f"{attrs.get('caption')} ({len(attrs.get('rows', []))} rows)"
        for field in ("description", "summary", "meaning"):
            if attrs.get(field):
                return str(attrs[field])[:160]
        return ""

    def _entry_response(self, row) -> dict:
        attrs = db.loads(row["attrs"]) or {}
        entry_id = row["entry_id"]
        result = {
            "id": entry_id, "type": row["type"], "key": row["key"], "resolved": bool(row["resolved"]),
            "summary": self._entry_summary(row), "path": row["path"], "line": row["line"],
            "permalink": permalink(row["path"], row["line"], attrs.get("end_line")) if row["path"] else None,
            "attrs": attrs,
        }
        links: list[dict] = []
        handler_relations = {"doit": "doit_handler", "dumpit": "dumpit_handler", "call": "handler", "hook": "hook_function",
                             "init": "init_function", "exit": "exit_function", "pre_exit": "pre_exit_function",
                             "exit_batch": "exit_batch_function", "proc_handler": "proc_handler", "table": "member_of",
                             "ops_table": "member_of", "proto_symbol_id": "func_proto"}
        linked: set[str] = set()
        for field, relation in handler_relations.items():
            value = attrs.get(field)
            if isinstance(value, str) and "::" in value:
                linked.add(value)
                links.append(make_link("symbol", value, relation, attrs.get("registered_with") if field in ("doit", "dumpit") else None,
                                       1.0 if field in ("doit", "dumpit") else None))
        if row["symbol_id"] and row["symbol_id"] not in linked:
            relation = "implemented_by" if row["type"] == "bpf_helper" else "defined_in"
            links.insert(0, make_link("symbol", row["symbol_id"], relation))
        elif not row["symbol_id"] and row["path"] and self.row("SELECT 1 FROM files WHERE path = ?", (row["path"],)):
            links.insert(0, make_link("file", row["path"], "defined_in", line=row["line"]))
        if row["type"] == "ops":
            for member, symbol_id in list((attrs.get("members") or {}).items())[:40]:
                links.append(make_link("symbol", symbol_id, "calls", member=member))
        if row["type"] == "kconfig":
            for path in (attrs.get("files") or [])[:25]:
                links.append(make_link("file", path, "builds", "makefile", 1.0))
        uses = self.rows(
            "SELECT path, line, symbol_id, use_kind FROM registry_uses WHERE entry_id = ? AND use_kind NOT LIKE 'member:%' AND use_kind NOT LIKE 'handler:%' ORDER BY path, line",
            (entry_id,),
        )
        if uses:
            result["use_count"] = len(uses)
            result["uses"] = [
                {"path": u["path"], "line": u["line"], "use_kind": u["use_kind"], "in": u["symbol_id"],
                 "permalink": permalink(u["path"], u["line"])}
                for u in uses[:30]
            ]
            for use in uses[:15]:
                if use["symbol_id"]:
                    links.append(make_link("symbol", use["symbol_id"], "used_at", use_kind=use["use_kind"], line=use["line"]))
        documentation = []
        for record in self.rows("SELECT * FROM doc_records WHERE registry_id = ? ORDER BY line", (entry_id,)):
            record_attrs = db.loads(record["attrs"]) or {}
            documentation.append({
                "record_id": record["record_id"], "doc_id": record["doc_id"],
                "permalink": self._record_permalink(record),
                **{k: record_attrs[k] for k in ("value_type", "default", "description", "rfc", "direction") if record_attrs.get(k)},
            })
            if record["record_id"] != entry_id:
                # (a record with the entry's own id is already merged in above)
                links.append(make_link("record", record["record_id"], "documented_by", "exact_name", 1.0))
        if documentation:
            result["documentation"] = documentation
        for doc_row in self.rows(
            "SELECT doc_id, method, confidence FROM registry_doc_links WHERE entry_id = ? ORDER BY confidence DESC LIMIT 15", (entry_id,)
        ):
            links.append(make_link("doc", doc_row["doc_id"], "documented_by", doc_row["method"], doc_row["confidence"], heading=self.doc_title(doc_row["doc_id"])))
            if doc_row["method"] == "netlink_spec" and "#op/" in doc_row["doc_id"]:
                family = doc_row["doc_id"].split("#", 1)[0].rsplit("/", 1)[-1][: -len(".yaml")]
                links.append(make_link("record", f"netlink/{family}/{doc_row['doc_id'].split('#op/', 1)[1]}", "specified_by", "netlink_spec", 1.0))
        capped, more = _cap_links(links)
        result["links"] = capped
        if more:
            result["links_truncated"] = more
        return result

    def _record_response(self, row) -> dict:
        attrs = db.loads(row["attrs"]) or {}
        result = {
            "id": row["record_id"], "type": row["dataset"], "key": row["key"],
            "summary": self._record_summary(row), "doc_id": row["doc_id"],
            "permalink": self._record_permalink(row), "attrs": attrs,
        }
        links = []
        if row["doc_id"]:
            links.append(make_link("doc", row["doc_id"], "documented_by", heading=self.doc_title(row["doc_id"])))
        if row["registry_id"]:
            links.append(make_link("registry", row["registry_id"], "defined_in", "exact_name", 1.0, match=attrs.get("registry_match")))
        for other in attrs.get("other_candidates") or []:
            links.append(make_link("registry", other, "defined_in", "name_match", 0.4))
        for field, relation in (("struct_symbol", "member_of"), ("ops_symbol", "implemented_by")):
            if attrs.get(field):
                links.append(make_link("symbol", attrs[field], relation))
        if attrs.get("implementation_file"):
            links.append(make_link("file", attrs["implementation_file"], "implemented_by"))
        for symbol_id in attrs.get("symbols") or []:
            links.append(make_link("symbol", symbol_id, "mentions", "name_match"))
        for group in ("kernel_helpers", "userspace_calls"):
            for helper in attrs.get(group) or []:
                if helper.get("registry_id"):
                    links.append(make_link("registry", helper["registry_id"], "uses"))
                links.append(make_link("doc", helper["doc_id"], "documented_by", heading=helper["name"] + "()"))
        if row["dataset"] == "ethtool_msg":
            op = self.row("SELECT ref_id FROM lookup_aliases WHERE type = 'netlink' AND alias = ?", (row["key"],))
            if op:
                links.append(make_link("record", op["ref_id"], "specified_by", "netlink_spec", 1.0))
        capped, more = _cap_links(links)
        result["links"] = capped
        if more:
            result["links_truncated"] = more
        return result

    def _attribute_details(self, family: str, attr_set: str | None, names: list[str] | None) -> list[dict] | None:
        if names is None:
            return None
        details = []
        for name in names:
            row = self.row("SELECT * FROM netlink_attrs WHERE family = ? AND attr_set = ? AND name = ?", (family, attr_set, name)) if attr_set else None
            if row is None:
                details.append({"name": name})
                continue
            extra = db.loads(row["attrs"]) or {}
            details.append({k: v for k, v in {
                "name": name, "type": row["type"], "doc": row["doc"], "enum": extra.get("enum"),
                "nested": extra.get("nested-attributes"), "checks": extra.get("checks"),
            }.items() if v is not None})
        return details

    def _netlink_response(self, key: str | None, limit: int, offset: int, filters: dict) -> dict:
        if not key:
            families = self.rows("SELECT * FROM netlink_families ORDER BY family")
            items = []
            for family in families:
                count = self.row("SELECT COUNT(*) AS n FROM netlink_ops WHERE family = ?", (family["family"],))["n"]
                attrs = db.loads(family["attrs"]) or {}
                items.append({"id": f"netlink/{family['family']}", "key": family["family"],
                              "summary": f"{family['protocol']}, {count} operations: {attrs.get('doc', '')[:100]}",
                              "next": _next("record", f"netlink/{family['family']}")})
            return {"type": "netlink", "total": len(items), "items": items}
        row = None
        family_name, _, op_name = key.partition("/")
        family = self.row("SELECT * FROM netlink_families WHERE family = ?", (family_name.replace("-", "_"),))
        if family is not None and op_name:
            row = self.row("SELECT * FROM netlink_ops WHERE family = ? AND op = ?", (family["family"], op_name))
        if family is not None and not op_name:
            attrs = db.loads(family["attrs"]) or {}
            ops = self.rows("SELECT op, value, doc FROM netlink_ops WHERE family = ? ORDER BY rowid", (family["family"],))
            links = [make_link("doc", family["spec_doc_id"], "specified_by", "netlink_spec", 1.0)]
            if attrs.get("registration_id"):
                links.append(make_link("registry", attrs["registration_id"], "registered_by", "netlink_spec", 1.0))
            for path in db.loads(family["generated_code"]) or []:
                if self.row("SELECT 1 FROM files WHERE path = ?", (path,)):
                    links.append(make_link("file", path, "generated_code", "netlink_spec", 1.0))
            return {
                "id": f"netlink/{family['family']}", "type": "netlink", "key": family["family"],
                "name": attrs.get("name"), "protocol": family["protocol"], "doc": attrs.get("doc"),
                "uapi_header": family["uapi_header"], "generated_code": db.loads(family["generated_code"]),
                "mcast_groups": attrs.get("mcast_groups"), "attribute_sets": attrs.get("attribute_sets"),
                "definitions": attrs.get("definitions"),
                "permalink": self._doc_permalink(family["spec_doc_id"]),
                "operations": [
                    {"id": f"netlink/{family['family']}/{o['op']}", "op": o["op"], "value": o["value"], "doc": o["doc"],
                     "next": _next("record", f"netlink/{family['family']}/{o['op']}")}
                    for o in ops
                ],
                "links": links,
            }
        if row is None:
            found = self.rows("SELECT DISTINCT ref_id FROM lookup_aliases WHERE type = 'netlink' AND alias = ?", (key.rsplit("/", 1)[-1],))
            found = [f for f in found if f["ref_id"].count("/") == 2]
            if family is not None:
                found = [f for f in found if f["ref_id"].startswith(f"netlink/{family['family']}/")] or found
            if len(found) == 1:
                _, family_name, op_name = found[0]["ref_id"].split("/", 2)
                row = self.row("SELECT * FROM netlink_ops WHERE family = ? AND op = ?", (family_name, op_name))
            elif found:
                return {"type": "netlink", "key": key, "ambiguous": True,
                        "candidates": [{"id": f["ref_id"], "next": _next("record", f["ref_id"])} for f in found[:30]]}
        if row is None:
            return error(
                f"netlink operation {key!r} not found in the {GITHUB_REF} index; keys look like \"rt_route/getroute\". "
                "List families with query_registry(type=\"netlink\") or try `search`",
                _search_next(key.replace("/", " "), kind="netlink"),
            )
        attrs = db.loads(row["attrs"]) or {}
        attr_set = attrs.get("attribute_set")
        dump = db.loads(row["dump_attrs"])
        family = self.row("SELECT * FROM netlink_families WHERE family = ?", (row["family"],))
        result = {
            "id": f"netlink/{row['family']}/{row['op']}", "type": "netlink", "family": row["family"], "op": row["op"],
            "protocol": family["protocol"], "value": row["value"], "doc": row["doc"],
            "message_constant": attrs.get("message_constant"), "attribute_set": attr_set,
            "fixed_header": attrs.get("fixed_header"), "kinds": attrs.get("kinds"),
            "notify": attrs.get("notify"), "mcast_group": attrs.get("mcgrp"),
            "do_request_attrs": self._attribute_details(row["family"], attr_set, db.loads(row["do_request_attrs"])),
            "do_reply_attrs": self._attribute_details(row["family"], attr_set, db.loads(row["do_reply_attrs"])),
            "dump_attrs": dump, "event_attrs": attrs.get("event_attrs"),
            "permalink": self._doc_permalink(row["doc_id"]),
        }
        result = {k: v for k, v in result.items() if v is not None}
        links = [make_link("doc", row["doc_id"], "specified_by", "netlink_spec", 1.0)]
        handlers = db.loads(row["handler_symbol_ids"]) or []
        for symbol_id in handlers:
            name = symbol_id.split("::")[-1]
            relation = "dumpit_handler" if "dump" in name else "doit_handler"
            links.append(make_link("symbol", symbol_id, relation, "netlink_spec", 0.9))
        if row["registration_id"]:
            links.append(make_link("registry", row["registration_id"], "registered_by", "netlink_spec", 1.0))
        if attrs.get("message_constant_symbol"):
            links.append(make_link("symbol", attrs["message_constant_symbol"], "defined_in", "name_match", 0.9))
        for path in db.loads(family["generated_code"]) or []:
            if self.row("SELECT 1 FROM files WHERE path = ?", (path,)):
                links.append(make_link("file", path, "generated_code", "netlink_spec", 1.0))
        if not handlers:
            result["resolved"] = False
            result["note"] = "no kernel handler was resolved for this operation (a notification, or handled outside the v1 scope)"
        result["links"] = links
        return result

    def _netlink_attr_response(self, key: str | None, limit: int, offset: int, filters: dict) -> dict:
        if not key:
            sql, params = "SELECT family, attr_set, name, type, doc FROM netlink_attrs", []
            clauses = []
            for field in ("family", "attr_set", "type"):
                if filters.get(field):
                    clauses.append(f"{field} = ?")
                    params.append(filters[field])
            if filters.get("prefix"):
                clauses.append("name LIKE ?")
                params.append(filters["prefix"] + "%")
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            total = self.row(f"SELECT COUNT(*) AS n FROM ({sql})", tuple(params))["n"]
            rows = self.rows(sql + " ORDER BY family, attr_set, rowid LIMIT ? OFFSET ?", (*params, limit, offset))
            return self._page("netlink_attr", total, offset, limit, [
                {"id": f"netlink_attr/{r['family']}/{r['attr_set']}/{r['name']}", "key": f"{r['family']}/{r['attr_set']}/{r['name']}",
                 "summary": f"{r['type']}: {r['doc'] or ''}"[:160]} for r in rows
            ])
        parts = key.split("/")
        if len(parts) == 3:
            rows = self.rows("SELECT * FROM netlink_attrs WHERE family = ? AND attr_set = ? AND name = ?", tuple(parts))
        elif len(parts) == 2:
            rows = self.rows("SELECT * FROM netlink_attrs WHERE family = ? AND name = ?", tuple(parts))
        else:
            rows = self.rows("SELECT * FROM netlink_attrs WHERE name = ? ORDER BY family, attr_set", (key,))
        if not rows:
            return error(
                f"netlink attribute {key!r} not found in the {GITHUB_REF} index; keys look like \"rt_route/route-attrs/rta-dst\"; try `search`",
                _search_next(key.rsplit("/", 1)[-1], kind="netlink_attr"),
            )
        if len(rows) > 1:
            return {"type": "netlink_attr", "key": key, "ambiguous": True, "count": len(rows), "candidates": [
                {"id": f"netlink_attr/{r['family']}/{r['attr_set']}/{r['name']}", "type": r["type"],
                 "next": _next("record", f"netlink_attr/{r['family']}/{r['attr_set']}/{r['name']}")} for r in rows[:40]
            ]}
        row = rows[0]
        extra = db.loads(row["attrs"]) or {}
        used_by = []
        for op in self.rows("SELECT * FROM netlink_ops WHERE family = ?", (row["family"],)):
            op_attrs = db.loads(op["attrs"]) or {}
            if op_attrs.get("attribute_set") != row["attr_set"]:
                continue
            dump = db.loads(op["dump_attrs"]) or {}
            where = [
                label for label, names in (
                    ("do request", db.loads(op["do_request_attrs"])), ("do reply", db.loads(op["do_reply_attrs"])),
                    ("dump request", dump.get("request")), ("dump reply", dump.get("reply")), ("event", op_attrs.get("event_attrs")),
                ) if names and row["name"] in names
            ]
            if where:
                used_by.append({"id": f"netlink/{op['family']}/{op['op']}", "in": where, "next": _next("record", f"netlink/{op['family']}/{op['op']}")})
        result = {
            "id": f"netlink_attr/{row['family']}/{row['attr_set']}/{row['name']}", "type": "netlink_attr",
            "family": row["family"], "attr_set": row["attr_set"], "name": row["name"], "value_type": row["type"],
            "doc": row["doc"], "attrs": extra, "used_by_operations": used_by,
            "permalink": self._doc_permalink(row["doc_id"]),
            "links": [make_link("doc", row["doc_id"], "specified_by", "netlink_spec", 1.0)]
                     + [make_link("record", u["id"], "used_at", "netlink_spec", 1.0) for u in used_by[:20]],
        }
        if extra.get("nested-attributes"):
            result["links"].append(make_link("doc", f"{row['doc_id'].split('#')[0]}#attr-set/{extra['nested-attributes']}", "contains", "netlink_spec", 1.0))
        return result

    @staticmethod
    def _page(kind: str, total: int, offset: int, limit: int, items: list[dict], extra: dict | None = None) -> dict:
        for item in items:
            item.setdefault("next", _next("registry", item["id"]))
        result = {"type": kind, "total": total, "offset": offset, "count": len(items), "items": items}
        if offset + len(items) < total:
            result["next_offset"] = offset + len(items)
        if extra:
            result.update(extra)
        return result

    def _list(self, kind: str, filters: dict, limit: int, offset: int) -> dict:
        if kind in REGISTRY_TYPES:
            table, type_column, id_column = "registry_entries", "type", "entry_id"
        else:
            table, type_column, id_column = "doc_records", "dataset", "record_id"
        clauses, params = [f"{type_column} = ?"], [kind]
        applied = {}
        for field, value in filters.items():
            if field == "prefix":
                clauses.append("key LIKE ? ESCAPE '\\'")
                params.append(str(value).replace("%", "\\%").replace("_", "\\_") + "%")
            elif field == "contains":
                clauses.append("key LIKE ? ESCAPE '\\'")
                params.append("%" + str(value).replace("%", "\\%").replace("_", "\\_") + "%")
            elif field == "path" and table == "registry_entries":
                clauses.append("path LIKE ?")
                params.append(str(value) + "%")
            elif field == "resolved" and table == "registry_entries":
                clauses.append("resolved = ?")
                params.append(1 if value else 0)
            elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(field)):
                clauses.append(f"json_extract(attrs, '$.{field}') = ?")
                params.append(value)
            else:
                return error(f"cannot filter on {field!r}; use prefix, contains, path, resolved or an attrs field name")
            applied[field] = value
        where = " AND ".join(clauses)
        total = self.row(f"SELECT COUNT(*) AS n FROM {table} WHERE {where}", tuple(params))["n"]
        rows = self.rows(f"SELECT * FROM {table} WHERE {where} ORDER BY key LIMIT ? OFFSET ?", (*params, limit, offset))
        summarize = self._entry_summary if table == "registry_entries" else self._record_summary
        items = [{"id": r[id_column], "key": r["key"], "summary": summarize(r)} for r in rows]
        extra = {"filter": applied} if applied else {}
        if kind in DOC_ONLY_FALLBACK and not offset:
            documented = self.row("SELECT COUNT(*) AS n FROM doc_records WHERE dataset = ?", (kind,))["n"]
            extra["note"] = f"listing {kind} entries found in code; {documented} documented {kind} records are attached to them where they match"
        return self._page(kind, total, offset, limit, items, extra)

    def query_registry(self, type: str, key: str | None = None, filter: dict | None = None,
                       limit: int = 50, offset: int = 0) -> dict:
        kind = (type or "").strip()
        valid = REGISTRY_TYPES + RECORD_TYPES
        if kind not in valid:
            return error(f"unknown registry type {kind!r}; code registries: {REGISTRY_TYPES}; doc records: {RECORD_TYPES}")
        limit = max(1, min(int(limit or 50), 200))
        offset = max(0, int(offset or 0))
        filters = dict(filter or {})
        key = key.strip() if isinstance(key, str) and key.strip() else None
        if key and key.startswith(kind + "/") and kind not in ("netlink",):
            # an id was passed where a key was expected
            if self.row("SELECT 1 FROM registry_entries WHERE entry_id = ? UNION SELECT 1 FROM doc_records WHERE record_id = ?", (key, key)):
                key = key[len(kind) + 1 :]
        if kind == "netlink":
            if key and key.startswith("netlink/"):
                key = key[len("netlink/"):]
            return self._netlink_response(key, limit, offset, filters)
        if kind == "netlink_attr":
            return self._netlink_attr_response(key, limit, offset, filters)
        if not key:
            return self._list(kind, filters, limit, offset)

        if kind in REGISTRY_TYPES:
            keys = [key]
            if kind == "sysctl":
                keys.append(key.replace("/proc/sys/", "").strip("/").replace("/", "."))
            if kind == "kconfig" and not key.startswith("CONFIG_"):
                keys.append("CONFIG_" + key)
            for candidate in keys:
                row = self.row("SELECT * FROM registry_entries WHERE entry_id = ?", (f"{kind}/{candidate}",))
                if row is not None:
                    return self._entry_response(row)
            found = []
            for candidate in keys:
                found = self.rows(
                    "SELECT e.* FROM lookup_aliases a JOIN registry_entries e ON e.entry_id = a.ref_id WHERE a.type = ? AND a.alias = ? ORDER BY e.resolved DESC, e.key",
                    (kind, candidate),
                )
                if not found:
                    found = self.rows(
                        "SELECT * FROM registry_entries WHERE type = ? AND (key LIKE ? ESCAPE '\\' OR key LIKE ? ESCAPE '\\') ORDER BY key LIMIT 60",
                        (kind, candidate.replace("_", "\\_") + "/%", candidate.replace("_", "\\_") + "@%"),
                    )
                if found:
                    break
            if len(found) == 1:
                return self._entry_response(found[0])
            if found:
                return {
                    "type": kind, "key": key, "ambiguous": True, "count": len(found),
                    "message": "several entries match this key; call query_registry again with one of these keys",
                    "candidates": [
                        {"id": r["entry_id"], "key": r["key"], "summary": self._entry_summary(r),
                         "next": _next("registry", r["entry_id"])} for r in found[:40]
                    ],
                }
        dataset = kind
        row = self.row("SELECT * FROM doc_records WHERE record_id = ?", (f"{dataset}/{key}",))
        if row is not None:
            return self._record_response(row)
        found = self.rows(
            "SELECT r.* FROM lookup_aliases a JOIN doc_records r ON r.record_id = a.ref_id WHERE a.type = ? AND a.alias = ? ORDER BY r.key",
            (dataset, key),
        )
        if not found:
            found = self.rows(
                "SELECT * FROM doc_records WHERE dataset = ? AND (key LIKE ? ESCAPE '\\' OR key LIKE ? ESCAPE '\\' OR key LIKE ? ESCAPE '\\') ORDER BY key LIMIT 80",
                (dataset, key.replace("_", "\\_") + "/%", key.replace("_", "\\_") + ".%", key.replace("_", "\\_") + "@%"),
            )
        if len(found) == 1:
            return self._record_response(found[0])
        if found:
            return {
                "type": kind, "key": key, "ambiguous": True, "count": len(found),
                "message": "several records match this key; call query_registry again with one of these keys",
                "candidates": [
                    {"id": r["record_id"], "key": r["key"], "summary": self._record_summary(r),
                     "next": _next("record", r["record_id"])} for r in found[:60]
                ],
            }
        return error(
            f"{kind} {key!r} not found in the {GITHUB_REF} index; list keys with query_registry(type=\"{kind}\") or try `search`",
            _search_next(key.rsplit("/", 1)[-1].rsplit(".", 1)[-1], kind=kind),
        )

    # ==================================================================================
    # find_references
    # ==================================================================================

    def find_references(self, name: str, path: str | None = None, ref_kind: str | None = None,
                        limit: int = 50, offset: int = 0) -> dict:
        name = (name or "").strip()
        if "::" in name:
            name = name.split("::", 1)[1].split("@", 1)[0]
        if not name:
            return error("name is empty; pass a bare symbol name such as fib_table_lookup")
        if ref_kind and ref_kind not in REF_KINDS:
            return error(f"unknown ref_kind {ref_kind!r}; use one of {REF_KINDS}")
        limit = max(1, min(int(limit or 50), 200))
        offset = max(0, int(offset or 0))
        name_row = self.row("SELECT name_id FROM ref_names WHERE name = ?", (name,))
        definitions = self.rows("SELECT * FROM symbols WHERE name = ? ORDER BY is_static, path LIMIT 10", (name,))
        if name_row is None:
            if definitions:
                return {"name": name, "total": 0, "groups": [], "definitions": [self.symbol_brief(d) for d in definitions],
                        "note": "defined in scope, but no other use of this name was found in the in-scope code"}
            return error(
                f"{name} is not an indexed symbol name at {GITHUB_REF} (it may be outside the v1 networking scope); try `search`",
                _search_next(name, types=["symbol"]),
            )
        clauses, params = ["r.name_id = ?"], [name_row["name_id"]]
        if path:
            clauses.append("f.path LIKE ?")
            params.append(path.lstrip("/") + "%")
        if ref_kind:
            clauses.append("r.ref_kind = ?")
            params.append(db.REF_KINDS[ref_kind])
        where = " AND ".join(clauses)
        base = f"FROM symbol_refs_data r JOIN files f ON f.rowid = r.file_id LEFT JOIN symbols s ON s.rowid = r.enclosing_symbol WHERE {where}"
        total = self.row(f"SELECT COUNT(*) AS n {base}", tuple(params))["n"]
        by_kind = {REF_KINDS[k]: n for k, n in self.rows(f"SELECT r.ref_kind, COUNT(*) {base} GROUP BY r.ref_kind", tuple(params))}
        rows = self.rows(
            f"SELECT f.path AS path, r.line AS line, r.ref_kind AS ref_kind, s.symbol_id AS enclosing, s.kind AS enclosing_kind "
            f"{base} ORDER BY f.path, r.line LIMIT ? OFFSET ?", (*params, limit, offset),
        )
        groups: dict[tuple[str, str | None], dict] = {}
        for row in rows:
            key = (row["path"], row["enclosing"])
            group = groups.get(key)
            if group is None:
                group = {"path": row["path"], "enclosing": row["enclosing"], "enclosing_kind": row["enclosing_kind"], "occurrences": []}
                if not row["enclosing"]:
                    group["note"] = "at file scope (a declaration, prototype or initializer)"
                groups[key] = group
            group["occurrences"].append({
                "line": row["line"], "ref_kind": REF_KINDS[row["ref_kind"]], "permalink": permalink(row["path"], row["line"]),
            })
        result = {
            "name": name, "total": total, "offset": offset, "count": len(rows), "by_kind": by_kind,
            "definitions": [dict(self.symbol_brief(d), next=_next("symbol", d["symbol_id"])) for d in definitions],
            "groups": list(groups.values()),
            "links": [make_link("symbol", g["enclosing"], "used_at") for g in groups.values() if g["enclosing"]][:MAX_LINKS],
        }
        if offset + len(rows) < total:
            result["next_offset"] = offset + len(rows)
            result["next"] = {"tool": "find_references", "args": {
                "name": name, **({"path": path} if path else {}), **({"ref_kind": ref_kind} if ref_kind else {}),
                "limit": limit, "offset": offset + len(rows)}}
        if len(definitions) > 1:
            result["note"] = "matching is by name: several definitions share this name, so uses of all of them are listed; narrow with `path`"
        return result
