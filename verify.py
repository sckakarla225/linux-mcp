"""Check a built linux-mcp end to end through a real MCP client session over stdio.

    .venv/bin/python verify.py

Starts server.py the way Cursor does, calls every tool and resource template, and checks
the answers against facts that hold at the pinned tag. Exits non-zero if any check fails.
It makes a handful of live GitHub fetches.
"""

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
failures: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    print(f"  {'ok  ' if condition else 'FAIL'} {label}" + (f"  -> {detail}" if not condition and detail != "" else ""))
    if not condition:
        failures.append(label)


def link_ids(result: dict, relation: str | None = None) -> list[str]:
    return [l.get("id") for l in result.get("links", []) if relation is None or l["relation"] == relation]


async def run() -> None:
    params = StdioServerParameters(command=sys.executable, args=[str(HERE / "server.py")], cwd="/")
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()

        async def call(tool: str, **args) -> dict:
            result = await session.call_tool(tool, args)
            return result.structured_content or json.loads(result.content[0].text)

        async def read_resource(uri: str) -> dict:
            return json.loads((await session.read_resource(uri)).contents[0].text)

        print("handshake")
        check("server name", init.server_info.name == "linux-mcp", init.server_info.name)
        check("instructions mention the workflow", "start with `search`" in (init.instructions or ""))
        tools = [tool.name for tool in (await session.list_tools()).tools]
        check("six tools", tools == ["search", "get_doc", "get_file", "get_symbol", "query_registry", "find_references"], tools)
        templates = [t.uri_template for t in (await session.list_resource_templates()).resource_templates]
        check("four resource templates", len(templates) == 4 and all(t.startswith("linux://") for t in templates), templates)

        print("search")
        hits = (await call("search", query="tcp_v4_rcv"))["hits"]
        check("identifier finds its symbol first", hits and hits[0]["id"] == "net/ipv4/tcp_ipv4.c::tcp_v4_rcv", hits[:1])
        check("hit has permalink and next", hits[0]["permalink"].startswith("https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_ipv4.c#L") and hits[0]["next"]["tool"] == "get_symbol")
        result = await call("search", query="TCPLossProbes")
        check("counter name finds the snmp entry", result["hits"][0]["id"] == "snmp/TcpExtTCPLossProbes", result["hits"][:1])
        result = await call("search", query="connection tracking", types=["file"], area="net")
        check("alias list maps 'connection tracking' to conntrack", "conntrack" in result.get("expanded_concepts", []) and all("conntrack" in h["id"] or "netfilter" in h["id"] for h in result["hits"][:5]), [h["id"] for h in result["hits"][:5]])
        result = await call("search", query="ECMP hashing")
        check("concept search reaches multipath hash", any("multipath_hash" in h["id"] for h in result["hits"]), [h["id"] for h in result["hits"][:6]])
        result = await call("search", query="fib lookup", kind="function", limit=10)
        check("kind filter returns only functions", all("(function)" in h["title"] for h in result["hits"]) and any(h["id"].endswith("::fib_table_lookup") for h in result["hits"]))
        check("unknown kind is an error", "error" in await call("search", query="x", kind="nope"))

        print("get_doc")
        outline = await call("get_doc", doc_id="networking/fib_trie.rst")
        check("doc outline lists sections", outline["section_count"] == 6 and outline["cluster"] == "Routing (L3)", outline.get("section_count"))
        section = await call("get_doc", doc_id="networking/fib_trie.rst#main-lookup-mechanism")
        check("section text is fetched live", section["text"].startswith("Main lookup mechanism") and section["text_lines"] == [119, 149], section.get("text_lines"))
        check("section permalink is pinned", section["permalink"].endswith("Documentation/networking/fib_trie.rst#L119-L149"))
        stale = [l for l in section["links"] if l["type"] == "unresolved" and l["raw_text"] == "fn_trie_lookup()"]
        check("renamed function is unresolved and stale", bool(stale) and stale[0]["stale"] is True and stale[0]["next"]["tool"] == "search", stale)
        check("resolved mention links to a symbol", "net/ipv4/fib_trie.c::fib_find_node" in link_ids(section, "mentions"))
        long_section = await call("get_doc", doc_id="networking/ip-sysctl.rst#tcp-variables")
        check("long section is capped at 400 lines", long_section["text"].count("\n") + 1 == 400 and "truncated" in long_section)
        continued = await call("get_doc", **long_section["truncated"]["next"]["args"])
        check("truncated.next reads on", continued["text_lines"][0] == long_section["text_lines"][1] + 1, continued.get("text_lines"))
        spec = await call("get_doc", doc_id="netlink/specs/rt_route.yaml#op/getroute")
        check("netlink spec op section", spec["text"].lstrip("- \n").startswith("name: getroute") and "netlink/rt_route/getroute" in link_ids(spec), spec["text"][:40])
        check("out-of-scope doc is an error with a next step", "next" in await call("get_doc", doc_id="filesystems/vfs.rst"))

        print("get_file")
        outline = await call("get_file", path="net/ipv4/fib_trie.c")
        names = {row[0]: row for row in outline["symbols"]}
        check("file outline has the symbol with its range", names.get("fib_table_lookup", [])[1:4] == ["function", 1444, 1648], names.get("fib_table_lookup"))
        check("file metadata", outline["kconfig"] == "CONFIG_INET" and outline["subsystem"] == "ipv4" and "fib" in outline["tags"] and "source" not in outline)
        check("file links to its doc", any(i.startswith("networking/fib_trie.rst#") for i in link_ids(outline, "documented_by")))
        ranged = await call("get_file", path="net/ipv4/fib_trie.c", start_line=1445, end_line=1446)
        check("line range is fetched live", ranged["source"].startswith("int fib_table_lookup(struct fib_table *tb"), ranged.get("source", "")[:60])
        capped = await call("get_file", path="net/core/dev.c", start_line=1, end_line=5000)
        check("line range is capped at 400", capped["end_line"] == 400 and capped["truncated"]["next"]["args"]["start_line"] == 401)
        outside = await call("get_file", path="fs/namei.c")
        check("out-of-scope path says so", "outside the v1 networking scope" in outside.get("error", ""), outside)

        print("get_symbol")
        symbol = await call("get_symbol", id_or_name="fib_table_lookup")
        check("bare name resolves", symbol["id"] == "net/ipv4/fib_trie.c::fib_table_lookup" and symbol["is_exported"] and "struct trie *t" in symbol["source"])
        check("symbol offers find_references", any(l["type"] == "references" and l["count"] > 5 for l in symbol["links"]))
        member = await call("get_symbol", id_or_name="net/ipv4/af_inet.c::inet_sendmsg")
        check("function knows the ops tables it sits in", any(l["relation"] == "member_of" and l["id"] == "ops/proto_ops/inet_stream_ops" and l["member"] == "sendmsg" for l in member["links"]))
        handler = await call("get_symbol", id_or_name="inet_rtm_getroute")
        check("function knows it is a netlink doit handler", "registration/rtnl/RTM_GETROUTE/PF_INET" in link_ids(handler, "doit_handler"), link_ids(handler))
        macro = await call("get_symbol", id_or_name="bpf_xdp_redirect_map")
        check("BPF_CALL function is extracted", macro["is_macro_generated"] and "bpf_helper/bpf_redirect_map" in link_ids(macro, "implements"))
        ambiguous = await call("get_symbol", id_or_name="fib_lookup")
        check("ambiguous name returns candidates without source", ambiguous.get("ambiguous") and len(ambiguous["candidates"]) == 2 and "source" not in ambiguous)
        check("unknown symbol suggests search", (await call("get_symbol", id_or_name="no_such_symbol_here")).get("next", {}).get("tool") == "search")

        print("query_registry")
        sysctl = await call("query_registry", type="sysctl", key="net.ipv4.tcp_rmem")
        check("sysctl joins code and docs", sysctl["attrs"]["proc_handler"] == "proc_dointvec_minmax" and sysctl["documentation"][0]["doc_id"] == "networking/ip-sysctl.rst#tcp-variables", sysctl.get("attrs"))
        check("sysctl accepts a /proc path", (await call("query_registry", type="sysctl", key="/proc/sys/net/ipv4/ip_forward")).get("id") == "sysctl/net.ipv4.ip_forward")
        registration = await call("query_registry", type="registration", key="rtnl/RTM_GETROUTE")
        check("shared rtnetlink message returns every family", registration.get("ambiguous") and any(c["key"] == "rtnl/RTM_GETROUTE/PF_INET6" for c in registration["candidates"]))
        registration = await call("query_registry", type="registration", key="rtnl/RTM_GETROUTE/PF_INET")
        check("registration links its handler", "net/ipv4/route.c::inet_rtm_getroute" in link_ids(registration, "doit_handler") and "netlink/rt_route/getroute" in link_ids(registration))
        snmp = await call("query_registry", type="snmp", key="TcpExtTCPLossProbes")
        check("snmp counter lists its increment site", snmp["attrs"]["mib"] == "LINUX_MIB_TCPLOSSPROBES" and snmp["uses"][0]["in"] == "net/ipv4/tcp_output.c::tcp_send_loss_probe", snmp.get("uses"))
        ops = await call("query_registry", type="ops", key="proto_ops/inet_stream_ops")
        check("ops table maps members to functions", ops["attrs"]["members"]["sendmsg"] == "net/ipv4/af_inet.c::inet_sendmsg")
        kconfig = await call("query_registry", type="kconfig", key="CONFIG_IP_MULTIPLE_TABLES")
        check("kconfig option lists the files it builds", kconfig["attrs"]["files"] == ["net/ipv4/fib_rules.c"] and kconfig["attrs"]["prompt"] == "IP: policy routing")
        helper = await call("query_registry", type="bpf_helper", key="bpf_redirect_map")
        check("bpf helper resolves through its func_proto", helper["attrs"]["impl_symbol_id"] == "net/core/filter.c::bpf_xdp_redirect_map" and helper["attrs"]["func_id"] == 51 and "BPF_PROG_TYPE_XDP" in helper["attrs"]["prog_types"], helper.get("attrs", {}).get("prog_types"))
        tracepoint = await call("query_registry", type="tracepoint", key="tcp_retransmit_skb")
        check("tracepoint lists its call site", tracepoint["uses"][0]["in"] == "net/ipv4/tcp_output.c::__tcp_retransmit_skb")
        netlink = await call("query_registry", type="netlink", key="rt_route/getroute")
        check("netlink op links spec, handlers and registration", netlink["value"] == "26" and "net/ipv4/route.c::inet_rtm_getroute" in link_ids(netlink, "doit_handler") and "registration/rtnl/RTM_GETROUTE" in link_ids(netlink, "registered_by"))
        check("netlink op by message constant", (await call("query_registry", type="netlink", key="RTM_GETROUTE")).get("id") == "netlink/rt_route/getroute")
        generated = await call("query_registry", type="netlink", key="netdev/dev-get")
        check("genetlink op resolves generated handlers", "net/core/netdev-genl.c::netdev_nl_dev_get_doit" in link_ids(generated, "doit_handler"))
        cacheline = await call("query_registry", type="net_cachelines", key="tcp_sock.snd_nxt")
        check("net_cachelines record", cacheline["attrs"]["fastpath_tx_access"] == "read_write" and "include/linux/tcp.h::tcp_sock" in link_ids(cacheline, "member_of"))
        listing = await call("query_registry", type="ops", filter={"struct_type": "tcp_congestion_ops"})
        check("list with a filter", listing["total"] >= 10 and any(i["key"] == "tcp_congestion_ops/cubictcp" for i in listing["items"]), listing.get("total"))
        page = await call("query_registry", type="snmp", limit=2, offset=4)
        check("list paging", page["count"] == 2 and page["offset"] == 4 and page["next_offset"] == 6)
        check("unknown type is an error", "error" in await call("query_registry", type="nope"))

        print("find_references")
        refs = await call("find_references", name="fib_table_lookup")
        enclosing = [g["enclosing"] for g in refs["groups"]]
        check("callers are grouped by enclosing function", "net/ipv4/fib_rules.c::fib4_rule_action" in enclosing and refs["by_kind"]["call"] >= 8, enclosing)
        refs = await call("find_references", name="inet_sendmsg", ref_kind="address_of", limit=5)
        check("address_of finds ops-table uses", refs["total"] >= 10 and refs["count"] == 5 and refs["next_offset"] == 5 and refs["groups"][0]["enclosing_kind"] == "ops_instance")
        refs = await call("find_references", name="sk_buff", path="net/ipv4/fib_", limit=5)
        check("path narrows results", refs["total"] < 100 and all(g["path"].startswith("net/ipv4/fib_") for g in refs["groups"]))
        check("unknown name suggests search", (await call("find_references", name="no_such_symbol_here")).get("next", {}).get("tool") == "search")

        print("resource templates")
        check("doc", (await read_resource("linux://doc/networking/fib_trie.rst%23main-lookup-mechanism")).get("heading") == "Main lookup mechanism")
        check("code", (await read_resource("linux://code/net/ipv4/fib_trie.c")).get("subsystem") == "ipv4")
        check("symbol", (await read_resource("linux://symbol/net/ipv4/fib_trie.c::fib_table_lookup")).get("kind") == "function")
        check("registry entry", (await read_resource("linux://registry/sysctl/net.ipv4.tcp_rmem")).get("id") == "sysctl/net.ipv4.tcp_rmem")
        check("doc record", (await read_resource("linux://registry/net_cachelines/tcp_sock.snd_nxt")).get("type") == "net_cachelines")


def main() -> None:
    asyncio.run(run())
    if failures:
        print(f"\n{len(failures)} check(s) failed: {failures}")
        sys.exit(1)
    print("\nall checks passed")


if __name__ == "__main__":
    main()
