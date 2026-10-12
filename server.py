import json
from urllib.parse import unquote

from mcp.server.mcpserver import MCPServer

import tools

mcp = MCPServer(
    name="linux-mcp",
    instructions=(
        "Read-only reference for Linux kernel networking internals at torvalds/linux v6.12, "
        "the kernel line used by Debian 13. Covers Documentation/networking, netlink, netlabel, "
        "bpf and infiniband, and the networking source: net/, include/net/, the networking parts "
        "of include/linux/ and include/uapi/linux/, networking tracepoints, the drivers/net/ "
        "framework, kernel/bpf/ and lib/dim/.\n"
        "Workflow: start with `search` unless you already have an identifier. Open results with "
        "`get_doc`, `get_file`, `get_symbol` or `query_registry`. Every response has a `links` "
        "list, and each link gives the tool and arguments that open it; follow links instead of "
        "searching again. Use `find_references` to see where a symbol is used.\n"
        "Cite the `permalink` of every source or doc passage you rely on. Treat links with low "
        "confidence or `resolved: false` as leads to verify, not facts."
    ),
)

_index: tools.Index | None = None


def index() -> tools.Index:
    global _index
    if _index is None:
        _index = tools.Index()
    return _index


@mcp.tool()
def search(
    query: str,
    types: list[str] | None = None,
    area: str | None = None,
    kind: str | None = None,
    limit: int = 20,
) -> dict:
    """Find docs, code files, symbols, registry entries and doc records for a question or identifier.

    Use this first when you don't have an identifier yet, e.g. "how is the route for an outgoing
    packet chosen", "ECMP hashing", "TCPLossProbes" or "tcp_v4_rcv". Searches file keyword tags,
    symbol names, signatures and kernel-doc comments, registry and record keys, and doc section text.

    Args:
        query: words or identifiers to search for.
        types: limit results to any of "doc", "file", "symbol", "registry", "record".
        area: limit code results to a top-level folder, e.g. "net", "include/net",
            "include/uapi/linux", "drivers/net", "kernel/bpf".
        kind: limit to a symbol kind ("function", "struct", "union", "enum", "macro", "global",
            "ops_instance", "typedef", "enum_constant") or a registry or record type ("sysctl",
            "ops", "netlink", ...).
        limit: maximum hits, default 20, maximum 50.

    Returns ranked hits. Each hit has type, id, title, a one-line snippet, permalink, and `next`
    (the tool and arguments that open it). Results come from the prebuilt index; no source text.
    """
    return index().search(query, types, area, kind, limit)


@mcp.tool()
def get_doc(doc_id: str) -> dict:
    """Read a section of the kernel documentation at v6.12, or list the sections of a doc file.

    Args:
        doc_id: a section id such as "networking/fib_trie.rst#main-lookup-mechanism" or
            "netlink/specs/rt_route.yaml#op/getroute", or a doc path such as
            "networking/fib_trie.rst" to get that file's section outline.

    For a section, returns the heading, the text (fetched live from GitHub and sliced to the
    section), permalink, parent and child sections, and `links` to every code file, symbol,
    registry entry and record the section mentions or pulls in with kernel-doc. Mentions that
    could not be resolved (e.g. renamed functions) are listed as unresolved with a `search`
    suggestion. For a doc path, returns the title, folder, topic cluster and the list of
    sections with their ids and line ranges. Text is capped at 400 lines; a longer section
    returns `truncated.next`, the call that reads on.
    """
    return index().get_doc(doc_id)


@mcp.tool()
def get_file(
    path: str,
    start_line: int | None = None,
    end_line: int | None = None,
) -> dict:
    """Get the outline of a source file at v6.12, or read a range of its lines.

    Use this to see what a file contains before reading it. To read one function or struct,
    prefer `get_symbol`.

    Args:
        path: repo path, e.g. "net/ipv4/fib_trie.c", "include/net/ip_fib.h", "net/ipv4/Kconfig".
        start_line: first line to read, 1-based. Omit both line arguments for the outline only.
        end_line: last line to read, inclusive. At most 400 lines per call.

    Without a range, returns metadata only: subsystem, the Kconfig option that builds the file,
    MAINTAINERS sections, keyword tags, header comment, the symbol outline (every function,
    struct, macro and global with its kind and line range), and `links` to the doc sections that
    cover the file and the registry entries defined in it. With a range, also returns those lines,
    fetched live from GitHub, with a permalink; the outline then lists only symbols in the range.
    """
    return index().get_file(path, start_line, end_line)


@mcp.tool()
def get_symbol(id_or_name: str) -> dict:
    """Read the definition of a function, struct, union, enum, macro or global variable at v6.12.

    Args:
        id_or_name: a symbol id such as "net/ipv4/fib_trie.c::fib_table_lookup", or a bare name
            such as "fib_table_lookup". If a bare name has several definitions (static functions
            in different files, or #ifdef variants), returns the candidates without source; call
            again with one of their ids.

    Returns the kind, signature, source (fetched live, with its kernel-doc comment), line range,
    permalink, the #ifdef condition it is compiled under, and whether it is static or exported.
    `links` point to its file, the doc sections that describe it, the registry entries it defines
    or belongs to (e.g. it is the `sendmsg` member of `inet_stream_ops`, or the doit handler for
    RTM_GETROUTE), and a `find_references` call with the number of references.
    """
    return index().get_symbol(id_or_name)


@mcp.tool()
def query_registry(
    type: str,
    key: str | None = None,
    filter: dict | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Look up kernel objects spread across many files, and structured records from the docs.

    Code registry types: "ops" (ops-table instances such as tcp_prot or a net_device_ops),
    "registration" (rtnetlink, generic netlink, nfnetlink, netfilter hooks, pernet, initcalls),
    "sysctl", "snmp", "tracepoint", "export", "kconfig", "bpf_helper".
    Doc record types: "netlink" (spec operations), "netlink_attr", "net_cachelines",
    "xfrm_counter", "ethtool_msg", "operstate", "proc_net_tcp", "bpf_prog_type",
    "bpf_map_type", "kfunc_flag", "btf_kind", "bpf_isa".

    Args:
        type: one of the types above.
        key: the exact key, e.g. "net.ipv4.tcp_rmem" (sysctl), "rtnl/RTM_GETROUTE"
            (registration), "TcpExtTCPLossProbes" (snmp), "proto_ops/inet_stream_ops" (ops),
            "CONFIG_IP_MULTIPLE_TABLES" (kconfig), "bpf_redirect_map" (bpf_helper),
            "rt_route/getroute" (netlink), "tcp_sock.snd_nxt" (net_cachelines).
            Omit to list entries of the type.
        filter: field filters when listing, e.g. {"prefix": "net.ipv4."},
            {"struct_type": "tcp_congestion_ops"}, {"mechanism": "netfilter"}.
        limit: page size when listing, default 50.
        offset: page start when listing.

    With a key, returns the entry with its type-specific fields and `links` to the symbol that
    defines it, the places in the code that use it (e.g. counter increments, trace calls), and
    its doc section or record. Sysctl and SNMP entries combine the code definition with the
    documented description. A key that matches several entries (e.g. "rtnl/RTM_GETROUTE", which
    each address family registers) returns the candidates. Without a key, returns a page of keys
    with one-line summaries. No source text; open linked symbols with `get_symbol`.
    """
    return index().query_registry(type, key, filter, limit, offset)


@mcp.tool()
def find_references(
    name: str,
    path: str | None = None,
    ref_kind: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List where a function, struct, macro or global variable is used in the in-scope code at v6.12.

    Use this for "who calls X", "where is this struct used" or "what reads this variable".

    Args:
        name: the bare symbol name, e.g. "fib_table_lookup".
        path: a file or folder prefix to narrow results, e.g. "net/ipv4/".
        ref_kind: "call", "address_of" (e.g. stored in an ops table), "type_use" or "other".
        limit: page size, default 50.
        offset: page start.

    Returns occurrences grouped by enclosing function, each with path, line, ref_kind,
    permalink, and a `get_symbol` link to the enclosing function. Matching is by name, so
    same-named static functions in other files also appear; narrow with `path`. No source text.
    """
    return index().find_references(name, path, ref_kind, limit, offset)


# Resource templates: the same identifiers for clients that read MCP resources directly.
# A "#" inside an identifier must be percent-encoded as "%23" in the URI.


def _as_json(result: dict) -> str:
    return json.dumps(result, indent=2)


@mcp.resource("linux://doc/{+doc_id}", mime_type="application/json")
def doc_resource(doc_id: str) -> str:
    """A doc section or doc file outline, e.g. linux://doc/networking/fib_trie.rst%23main-lookup-mechanism"""
    return _as_json(index().get_doc(unquote(doc_id)))


@mcp.resource("linux://code/{+path}", mime_type="application/json")
def code_resource(path: str) -> str:
    """The outline of a source file, e.g. linux://code/net/ipv4/fib_trie.c"""
    return _as_json(index().get_file(unquote(path)))


@mcp.resource("linux://symbol/{+symbol_id}", mime_type="application/json")
def symbol_resource(symbol_id: str) -> str:
    """A symbol definition, e.g. linux://symbol/net/ipv4/fib_trie.c::fib_table_lookup"""
    return _as_json(index().get_symbol(unquote(symbol_id)))


@mcp.resource("linux://registry/{type}/{+key}", mime_type="application/json")
def registry_resource(type: str, key: str) -> str:
    """A registry entry or doc record, e.g. linux://registry/sysctl/net.ipv4.tcp_rmem"""
    return _as_json(index().query_registry(type, unquote(key)))


if __name__ == "__main__":
    index()  # fail at startup, with a clear message, if index.db has not been built
    mcp.run()
