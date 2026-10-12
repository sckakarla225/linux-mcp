# linux-mcp

A local MCP server for querying Linux kernel networking internals: documentation and source,
linked to each other.

## Overview

- **Read-only, educational, local.** Cursor (or any MCP client) starts it over stdio. Nothing
  is deployed and nothing in the kernel tree is modified.
- **Source of truth:** [`torvalds/linux`](https://github.com/torvalds/linux/tree/v6.12) at the
  tag `v6.12`, the kernel line Debian 13 ships. Every read uses this tag, never `master`, so
  line numbers are stable and every answer can cite a permalink.
- **No local clone.** A prebuilt SQLite index (`index.db`) holds identifiers, line ranges,
  metadata, tags and links. Source and documentation text is fetched live from GitHub when a
  tool needs it.
- **v1 scope: networking only.**
  - Docs: `Documentation/networking`, `netlink`, `netlabel`, `bpf`, `infiniband`
    (203 files; vendor NIC guides, per-driver devlink pages and legacy protocol docs are left out).
  - Code: `net/` (38 subsystems), `include/net/`, the networking parts of `include/linux/`
    and `include/uapi/linux/`, 21 networking tracepoint headers, the `drivers/net/` framework
    (virtual devices, bonding, team, vxlan, ipvlan, phy, mdio, pcs, netdevsim, wireguard),
    `kernel/bpf/`, `lib/dim/` and `lib/net_utils.c` (2,315 files).
  - Deferred: VFS, processes and scheduling, mm, security, syscalls, device drivers.

The exact scope rules are in [`scope.py`](scope.py).

## Setup

Prerequisites: Python 3.13 and a GitHub token (a classic token with no scopes, or a
fine-grained token with public read access, is enough).

```bash
cd linux-mcp
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Add the token to the `.env` file at the repo root (it is gitignored):

```bash
echo 'GITHUB_TOKEN=<your token>' >> .env
```

A `GITHUB_TOKEN` already set in the environment takes precedence over `.env`. The server and
the index build both stop with a clear error if the token is missing.

Build the index (see the next section), then register the server with Cursor.

Project config, `.cursor/mcp.json` at the root of this repo's workspace:

```json
{
  "mcpServers": {
    "linux-mcp": {
      "command": "${workspaceFolder}/.venv/bin/python",
      "args": ["${workspaceFolder}/server.py"]
    }
  }
}
```

Global config, `~/.cursor/mcp.json`, to use it from any workspace. Use absolute paths here:

```json
{
  "mcpServers": {
    "linux-mcp": {
      "command": "/absolute/path/to/linux-mcp/.venv/bin/python",
      "args": ["/absolute/path/to/linux-mcp/server.py"]
    }
  }
}
```

Neither file holds a secret: the token is read from `.env`.

## Building the index

```bash
.venv/bin/python build_index.py
```

- Takes about 35 seconds: 14 to fetch, 20 to parse and index.
- GitHub usage: about 10 REST API calls (tree listings) and about 2,520 file downloads from
  `raw.githubusercontent.com`. In testing the downloads did not count against the REST API
  rate limit.
- Writes `index.db` (about 80 MB). It is **built locally, not committed**; the repo
  `.gitignore` excludes it. The build is deterministic for a given tag and index code.
- `--cache-dir DIR` keeps the fetched files on disk so a rebuild takes about 25 seconds and
  fetches nothing. `--stats` prints the index statistics as JSON. `--output PATH` writes
  elsewhere.

Rebuild when the index code changes (anything under `indexer/`, `scope.py` or `db.py`) or
when the pinned tag changes. The server reads `index.db` at startup, so restart it afterwards.

Check a build end to end:

```bash
.venv/bin/python verify.py
```

This starts the server the way Cursor does, runs an MCP client session over stdio against
every tool and resource template, and exits non-zero if an answer is wrong.

## Resources

Four kinds of resource, all pinned to `v6.12` and linked to each other. The folder-by-folder
analysis behind them is in the plan (`~/.cursor/plans/linux_mcp.plan.md`).

| Resource | Identifier | Example | What the index holds |
| --- | --- | --- | --- |
| Documentation | doc path, plus `#` and a heading slug | `networking/fib_trie.rst#main-lookup-mechanism`, `netlink/specs/rt_route.yaml#op/getroute` | 203 files, 2,276 sections with line ranges, 4,597 code mentions (3,773 resolved), 92 kernel-doc directives |
| Code | repo path | `net/ipv4/fib_trie.c` | 2,315 files with area, subsystem, the `CONFIG_` option that builds each, MAINTAINERS sections, header comment and up to 25 keyword tags |
| Symbols | `path::name` (`@line` when a file defines the name twice) | `net/ipv4/fib_trie.c::fib_table_lookup` | 80,150 definitions with kind, line range, signature, `#ifdef` guard and kernel-doc comment; 565,369 references |
| Registries and doc records | `type/key` | `sysctl/net.ipv4.tcp_rmem`, `registration/rtnl/RTM_GETROUTE/PF_INET`, `net_cachelines/tcp_sock.snd_nxt` | see below |

Symbol kinds: `function`, `struct`, `union`, `enum`, `macro`, `global`, `ops_instance`, plus
`typedef` and `enum_constant` (so that names such as `RTM_GETROUTE` can be found).

Code registries (kernel objects spread over many files):

| Type | Key | Entries |
| --- | --- | --- |
| `ops` | `<struct type>/<instance>` | 2,667 initialized ops tables, with members mapped to functions |
| `registration` | `rtnl/<MSG>/<FAMILY>`, `genl/<family>`, `nfnl/<MSG>`, `netfilter/<hook>/<pf>/<hooknum>`, `pernet/<ops>`, `initcall/<fn>` | 90 rtnetlink, 25 generic netlink, 82 nfnetlink, 64 netfilter hooks, 168 pernet, 1,049 initcalls |
| `sysctl` | dotted path, e.g. `net.ipv4.tcp_rmem` | 534 |
| `snmp` | name as `nstat` shows it, e.g. `TcpExtTCPLossProbes` | 420, with increment sites |
| `tracepoint` | event name | 110, with call sites |
| `export` | symbol name | 3,495 |
| `kconfig` | `CONFIG_*` | 835, with the files each builds |
| `bpf_helper` | helper name | 211, from the comment block in `include/uapi/linux/bpf.h` |

Doc records (structured data parsed out of the docs): `netlink` (18 families, 236
operations), `netlink_attr` (2,130), `net_cachelines` (675), `sysctl` (413, of which 411 are
matched to a code entry), `snmp` (108, 107 matched), `xfrm_counter` (30), `ethtool_msg` (86),
`operstate` (7), `proc_net_tcp` (21), `bpf_prog_type` (94), `bpf_map_type` (16),
`kfunc_flag` (13), `btf_kind` (19), `bpf_isa` (12).

Keyword tags come from MAINTAINERS sections, Kconfig prompts, linked doc titles, registry
entries, header comments and symbol names, ranked by TF-IDF. A curated alias list
([`indexer/aliases.py`](indexer/aliases.py)) folds synonyms into one tag, so "connection
tracking" finds `nf_conntrack` files and "generic receive offload" finds `net/core/gro.c`.

## Tools

Start with `search`, open a result with one of the four readers, then follow `links`.

### `search(query, types?, area?, kind?, limit?)`

Find docs, files, symbols, registry entries and doc records for words or an identifier.
`types` limits to `doc`, `file`, `symbol`, `registry`, `record`; `area` to a code folder;
`kind` to a symbol kind or a registry or record type. Returns ranked hits, no source text.

```jsonc
search(query="tcp_v4_rcv")
{"query": "tcp_v4_rcv", "count": 1, "hits": [{
  "type": "symbol", "id": "net/ipv4/tcp_ipv4.c::tcp_v4_rcv", "title": "tcp_v4_rcv (function)",
  "snippet": "int tcp_v4_rcv(struct sk_buff *skb)",
  "permalink": "https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_ipv4.c#L2176-L2436",
  "next": {"tool": "get_symbol", "args": {"id_or_name": "net/ipv4/tcp_ipv4.c::tcp_v4_rcv"}}}]}
```

### `get_doc(doc_id)`

A doc path returns the file's outline (title, cluster, sections with line ranges). A section
id returns its text, fetched live, with links to everything it mentions.

```jsonc
get_doc(doc_id="networking/fib_trie.rst#main-lookup-mechanism")
{"doc_id": "networking/fib_trie.rst#main-lookup-mechanism", "heading": "Main lookup mechanism",
 "title": "LC-trie implementation notes", "cluster": "Routing (L3)", "start_line": 119, "end_line": 149,
 "permalink": "https://github.com/torvalds/linux/blob/v6.12/Documentation/networking/fib_trie.rst#L119-L149",
 "text": "Main lookup mechanism\n---------------------\nfn_trie_lookup() is the main lookup function. ...",
 "links": [
   {"type": "unresolved", "raw_text": "fn_trie_lookup()", "mention_kind": "function", "stale": true,
    "relation": "mentions", "next": {"tool": "search", "args": {"query": "fn_trie_lookup"}}},
   {"type": "symbol", "id": "net/ipv4/fib_trie.c::fib_find_node", "relation": "mentions",
    "method": "name_match", "confidence": 0.9, "next": {"tool": "get_symbol", "args": {...}}}, ...]}
```

Text is capped at 400 lines. A longer section returns `truncated.next`, a `get_doc` call
whose id ends in `@L<start>-L<end>` and reads on.

### `get_file(path, start_line?, end_line?)`

Without a range: metadata, tags and the symbol outline. With a range: those lines too
(at most 400), and the outline narrows to the symbols in the range.

```jsonc
get_file(path="net/ipv4/fib_trie.c")
{"path": "net/ipv4/fib_trie.c", "area": "net", "subsystem": "ipv4", "file_type": "c", "line_count": 3068,
 "kconfig": "CONFIG_INET", "maintainers": ["NETWORKING [IPv4/IPv6]", "NETWORKING [GENERAL]", "THE REST"],
 "tags": ["fib", ...], "symbol_counts": {"function": 86, "struct": 7, "macro": 17, ...},
 "symbol_columns": ["name", "kind", "start_line", "end_line", "id (only when it is not <path>::<name>)"],
 "symbols": [["call_fib_entry_notifier", "function", 76, 91], ..., ["fib_table_lookup", "function", 1444, 1648], ...],
 "links": [{"type": "registry", "id": "kconfig/CONFIG_INET", "relation": "built_by", ...},
           {"type": "doc", "id": "networking/fib_trie.rst#main-lookup-mechanism", "relation": "documented_by", ...}]}
```

### `get_symbol(id_or_name)`

The definition of one symbol, with its source fetched live. A bare name with several
definitions returns the candidates and no source.

```jsonc
get_symbol(id_or_name="inet_rtm_getroute")
{"id": "net/ipv4/route.c::inet_rtm_getroute", "kind": "function", "start_line": 3211, "end_line": 3378,
 "signature": "static int inet_rtm_getroute(struct sk_buff *in_skb, struct nlmsghdr *nlh, struct netlink_ext_ack *extack)",
 "is_static": true, "is_exported": false, "ifdef_guard": null,
 "permalink": "https://github.com/torvalds/linux/blob/v6.12/net/ipv4/route.c#L3211-L3378",
 "source": "static int inet_rtm_getroute(struct sk_buff *in_skb, struct nlmsghdr *nlh,\n...",
 "links": [{"type": "file", "id": "net/ipv4/route.c", "relation": "defined_in", ...},
           {"type": "registry", "id": "registration/rtnl/RTM_GETROUTE/PF_INET", "relation": "doit_handler", ...},
           {"type": "references", "id": "inet_rtm_getroute", "relation": "used_at", "count": 1,
            "next": {"tool": "find_references", "args": {"name": "inet_rtm_getroute"}}}]}
```

### `query_registry(type, key?, filter?, limit?, offset?)`

With a key: one entry with its type-specific fields. Without: a page of keys. `filter` takes
`prefix`, `contains`, `path`, `resolved`, or any field of the entry, e.g.
`{"struct_type": "tcp_congestion_ops"}` or `{"mechanism": "netfilter"}`.

```jsonc
query_registry(type="sysctl", key="net.ipv4.tcp_rmem")
{"id": "sysctl/net.ipv4.tcp_rmem", "resolved": true,
 "summary": "/proc/sys/net/ipv4/tcp_rmem (table ipv4_net_table, handler proc_dointvec_minmax)",
 "permalink": "https://github.com/torvalds/linux/blob/v6.12/net/ipv4/sysctl_net_ipv4.c#L1399",
 "attrs": {"data": "&init_net.ipv4.sysctl_tcp_rmem", "mode": "0644", "proc_handler": "proc_dointvec_minmax", ...},
 "documentation": [{"doc_id": "networking/ip-sysctl.rst#tcp-variables",
   "value_type": "vector of 3 INTEGERs: min, default, max", "description": "min: Minimal size of receive buffer ..."}],
 "links": [{"type": "symbol", "id": "net/ipv4/sysctl_net_ipv4.c::ipv4_net_table", "relation": "member_of", ...},
           {"type": "doc", "id": "networking/ip-sysctl.rst#tcp-variables", "relation": "documented_by", ...}]}
```

Keys are forgiving where that is unambiguous: `tcp_rmem`, `/proc/sys/net/ipv4/tcp_rmem`,
`tcp_prot` and `RTM_GETROUTE` (for `netlink`) all resolve. A key that matches several entries
returns them as candidates: `rtnl/RTM_GETROUTE` is registered by six address families.

### `find_references(name, path?, ref_kind?, limit?, offset?)`

Where a name is used, grouped by enclosing function. `ref_kind` is `call`, `address_of`
(stored in an ops table or passed as a callback), `type_use` or `other`.

```jsonc
find_references(name="fib_table_lookup", path="net/ipv4/fib_rules.c")
{"name": "fib_table_lookup", "total": 1, "by_kind": {"call": 1},
 "definitions": [{"id": "net/ipv4/fib_trie.c::fib_table_lookup", ...}],
 "groups": [{"path": "net/ipv4/fib_rules.c", "enclosing": "net/ipv4/fib_rules.c::fib4_rule_action",
   "occurrences": [{"line": 137, "ref_kind": "call",
     "permalink": "https://github.com/torvalds/linux/blob/v6.12/net/ipv4/fib_rules.c#L137"}]}],
 "links": [{"type": "symbol", "id": "net/ipv4/fib_rules.c::fib4_rule_action", "relation": "used_at", ...}]}
```

### Links

Every response has a `links` list. A link names the tool and arguments that open the linked
resource, so an agent moves between docs, files, symbols and registries without searching again:

```json
{
  "type": "symbol",
  "id": "net/ipv4/route.c::inet_rtm_getroute",
  "relation": "doit_handler",
  "method": "rtnl_register",
  "confidence": 1.0,
  "next": {"tool": "get_symbol", "args": {"id_or_name": "net/ipv4/route.c::inet_rtm_getroute"}}
}
```

- `type` decides the tool: `doc` opens with `get_doc`, `file` with `get_file`, `symbol` with
  `get_symbol`, `registry` and `record` with `query_registry`. `references` opens
  `find_references`. `unresolved` carries the raw text and a `search` suggestion.
- `relation` says why the two are linked (`mentions`, `kernel_doc`, `contains`, `defined_in`,
  `documented_by`, `member_of`, `doit_handler`, `dumpit_handler`, `used_at`, `builds`, ...).
- `method` and `confidence` come from the index. A name defined in several files links to each
  candidate with a lower confidence. Lists are capped at 60 links; `links_truncated` counts the rest.
- A tool that cannot answer returns `{"error": ..., "next": {...}}` naming the next step,
  rather than raising.

### End to end: how does Linux choose a route for an outgoing IPv4 packet?

1. `search(query="ip route output", kind="function")` returns
   `net/ipv4/route.c::ip_route_output_key_hash_rcu` among the hits.
2. `get_symbol("ip_route_output_key_hash_rcu")` returns
   [`route.c#L2631-L2799`](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/route.c#L2631-L2799):
   it fills in the flow key, calls `fib_lookup()`, then `fib_select_path()`.
3. `get_symbol("fib_lookup")` is ambiguous on purpose: it returns the two `#ifdef` variants in
   `include/net/ip_fib.h`, one compiled with `CONFIG_IP_MULTIPLE_TABLES` (policy routing) and one
   without. Both end in `fib_table_lookup()`.
4. `get_symbol("fib_table_lookup")` returns the trie walk at
   [`fib_trie.c#L1444-L1648`](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/fib_trie.c#L1444-L1648).
   `find_references("fib_table_lookup")` confirms the callers, including `fib4_rule_action`.
5. `get_doc("networking/fib_trie.rst#main-lookup-mechanism")` gives the design notes, and
   flags that the doc's `fn_trie_lookup()` no longer exists under that name.
6. `get_symbol("fib_select_path")` and `query_registry("sysctl", "net.ipv4.fib_multipath_hash_policy")`
   cover the last step: picking one next hop when the route has several.

From the other direction, `query_registry("netlink", "rt_route/getroute")` ties `ip route get`
to the kernel: the spec operation, the `RTM_GETROUTE` registrations, and `inet_rtm_getroute`.

## Resource templates

The same identifiers for clients that read MCP resources directly. Each returns the JSON the
matching tool returns.

| URI | Same as |
| --- | --- |
| `linux://doc/{doc_id}` | `get_doc` |
| `linux://code/{path}` | `get_file` (outline) |
| `linux://symbol/{symbol_id}` | `get_symbol` |
| `linux://registry/{type}/{key}` | `query_registry` (code registries and doc records) |

Write a `#` in an identifier as `%23`:
`linux://doc/networking/fib_trie.rst%23main-lookup-mechanism`. There are no prompts in v1.

## Project layout

```text
linux-mcp/
├── server.py          # MCPServer: instructions, the six tools, the resource templates (stdio entry point)
├── tools.py           # tool implementations: index queries, live fetches, links, paging, errors
├── github.py          # GitHub client: tree listings, raw fetches, in-memory cache, permalinks
├── db.py              # index.db schema and read-only connection
├── scope.py           # which doc and code paths are in the v1 scope; doc topic clusters
├── config.py          # loads GITHUB_TOKEN from .env; repo and ref constants
├── build_index.py     # command that builds index.db
├── verify.py          # end-to-end check through an MCP client session
├── requirements.txt   # pinned packages (pip freeze)
├── index.db           # the built index (gitignored)
└── indexer/
    ├── build.py       # build pipeline: fetch, parse, link, tag, write
    ├── corpus.py      # lists and fetches the in-scope files
    ├── docs.py        # doc sections (RST, plain text, YAML specs), mentions, kernel-doc directives
    ├── records.py     # structured doc datasets (sysctls, counters, net_cachelines, BPF tables, ...)
    ├── netlink.py     # netlink YAML specs: families, operations, attributes
    ├── cparse.py      # tree-sitter symbol extraction, with rules for kernel macros
    ├── ctext.py       # text-level C helpers: comment stripping, call matching, initializers
    ├── symbols.py     # symbol table and identifiers
    ├── registries.py  # ops tables, registrations, sysctls, SNMP, tracepoints, exports, Kconfig, BPF helpers
    ├── buildsys.py    # Kconfig, Makefile and MAINTAINERS parsing
    ├── refs.py        # reference index
    ├── links.py       # doc-to-code and record-to-registry resolution
    ├── tags.py        # keyword tags (TF-IDF)
    ├── aliases.py     # curated concept aliases
    └── model.py       # in-memory types shared by the build steps
```

## Limitations

- **Search is keyword search.** It ranks by full-text match, tags and how widely a file or
  name is used. It has no semantic understanding, so a question phrased far from the kernel's
  vocabulary does better as two or three key terms ("ip route output" rather than "how is the
  route for an outgoing packet chosen").
- **References are name-based.** `find_references` matches names, not resolved symbols. A
  local variable or a same-named static function in another file counts as a use; narrow with
  `path`. Member accesses (`x->name`) are not counted.
- **Unresolved and stale doc mentions.** About 18% of the code names written in docs have no
  definition in the index. They are returned as `unresolved`, never guessed. `stale: true`
  means a path does not exist at `v6.12`, or a name in a networking doc occurs nowhere in the
  in-scope source (renamed or removed, or occasionally a userspace or example name). A stale
  path whose file name exists exactly once elsewhere is linked there at confidence 0.5.
- **Macro-generated definitions.** `BPF_CALL_*`, `SYSCALL_DEFINE*` and `DEFINE_*` are handled
  by rule. Other generating macros are not expanded: 134 regions in 2,193 files do not parse
  cleanly (functions inside them are recovered by coding-style pattern), 48 exports and 12
  registrations point at names with no extracted definition, and macro-built sysctls
  (`DEVINET_SYSCTL_*`) carry the macro arguments instead of resolved fields. Entries like
  these are marked `resolved: false`.
- **Per-device sysctls** use placeholders in their key: `net.ipv4.conf.<dev>.forwarding`,
  `net.<proto>.neigh.<dev>.gc_stale_time`.
- **BPF helpers:** 55 of 211 are documented in `bpf.h` but implemented outside the scope
  (tracing, cgroup), so they have a description and no implementation link.
- **Netlink operations:** 195 of 236 link to a kernel handler. The rest are notifications, or
  families handled outside the scope (`dpll`).
- **Excluded code and docs.** Wireless, Bluetooth, CAN, ATM, 802.15.4, NFC, SunRPC, TIPC,
  RxRPC and similar `net/` subsystems, vendor NIC drivers, `tools/`, `drivers/infiniband/`,
  and every `Documentation/` folder other than the five listed. Asking for one of these
  returns an out-of-scope error with a GitHub link, not an empty result.
- **In-memory caching only.** Fetched files are cached for the life of the server process and
  never written to disk, so the first read of a file after a restart costs one request.
- **GitHub rate limits.** Live reads are one request per uncached file. If GitHub rate-limits
  the token, the tool returns the error with the reset time; the index-only tools (`search`,
  `query_registry`, `find_references`, outlines) keep working.
- **Blob check.** Each live fetch is compared with the blob SHA recorded at build time. A
  mismatch adds a `warning` to the response; rebuild the index if you see one.

## Extending

**Add a doc folder.** Add it to `DOC_FOLDERS` and `FOLDER_CLUSTERS` in `scope.py`, with any
exclusions. Sections, mentions and links come for free. For a new structured dataset, add a
parser to `indexer/records.py`, route the file in `extract_records`, and add the dataset name
to `RECORD_TYPES` in `tools.py`.

**Add a code folder.** Extend `code_in_scope` in `scope.py` (and `AREAS` for a new top-level
area). If the folder is under a root that is not yet listed, add the root to
`KNOWN_PATH_ROOTS` in `indexer/corpus.py`. Symbols, references, tags and the generic
registries (ops tables, exports, Kconfig, initcalls) need nothing else.

**Add a registry type.** Add a `build_*` method to `RegistryBuilder` in
`indexer/registries.py` and call it from `build_all`, add the type to `REGISTRY_TYPES` in
`tools.py`, and give it a one-line summary in `Index._entry_summary`.

**Add a concept alias.** Add a line to `CONCEPTS` in `indexer/aliases.py`. It affects both
file tags and query expansion.

**Move to a newer kernel tag.** Change `GITHUB_REF` in `config.py` and rebuild. Then re-check
the things tied to one release: the scope lists in `scope.py` (files move), `GENERATED_CODE`
and the message prefixes in `indexer/netlink.py`, `SNMP_TABLES` in `indexer/registries.py`,
and the facts asserted in `verify.py`.

**Verify.** After any of these, rebuild and run `.venv/bin/python verify.py`. It is a real MCP
client session (`mcp.ClientSession` over `stdio_client`), so it also shows how to drive the
server from a script. `build_index.py --stats` prints counts to compare before and after.
