"""Code registries: kernel objects that are spread across many files, grouped by type.

ops tables, registrations (rtnetlink, generic netlink, nfnetlink, netfilter hooks, pernet,
initcalls), sysctls, SNMP counters, tracepoints, exported symbols, Kconfig options and BPF
helpers.
"""

import re

from indexer import buildsys
from indexer.ctext import (
    LineIndex, bare_identifier, find_calls, initializer_of, matching_close, parse_initializer,
    split_top_level, strip_comments, unquote,
)
from indexer.model import RegistryEntry, RegistryUse, SymbolIndex, SymbolRow

# struct types that count as an ops table even when no member resolves to a function
OPS_STRUCT_TYPES = {
    "proto", "proto_ops", "net_device_ops", "pernet_operations", "nf_hook_ops", "Qdisc_ops",
    "Qdisc_class_ops", "tcp_congestion_ops", "rtnl_link_ops", "rtnl_af_ops", "genl_family",
    "nla_policy", "seq_operations", "bpf_func_proto", "ethtool_ops", "header_ops",
    "net_protocol", "inet6_protocol", "inet_protosw", "packet_type", "notifier_block",
    "file_operations", "proc_ops", "bpf_verifier_ops", "bpf_prog_ops", "bpf_map_ops",
    "tcf_proto_ops", "tc_action_ops", "xfrm_type", "xfrm_state_afinfo", "xfrm_policy_afinfo",
    "nf_conntrack_l4proto", "nft_expr_ops", "nft_expr_type", "xt_target", "xt_match",
    "dst_ops", "neigh_ops", "neigh_table", "fib_rules_ops", "request_sock_ops",
    "inet_connection_sock_af_ops", "tcp_request_sock_ops", "timewait_sock_ops",
    "net_offload", "offload_callbacks", "lwtunnel_encap_ops", "ip_tunnel_encap_ops",
    "udp_tunnel_nic_info", "switchdev_ops", "dsa_switch_ops", "devlink_ops", "phy_driver",
    "mdio_driver", "phylink_mac_ops", "phylink_pcs_ops", "genl_ops", "genl_small_ops",
    "genl_split_ops", "nfnl_callback", "nfnetlink_subsystem", "rtnl_msg_handler",
    "tcp_ulp_ops", "mptcp_sched_ops", "smc_hashinfo", "bpf_struct_ops", "xdp_metadata_ops",
    "xsk_tx_metadata_ops", "net_device_path_ops", "l3mdev_ops", "ndisc_ops", "ipv6_stub",
    "inet_frags", "rhashtable_params", "ctl_table",
}
OPS_SUFFIXES = ("_ops", "_operations", "_afinfo", "_driver", "_family", "_proto", "_protocol")
MAX_ARRAY_ELEMENTS = 400

INITCALL_RE = re.compile(
    r"^(module_init|module_exit|__initcall|pure_initcall|core_initcall|postcore_initcall|"
    r"arch_initcall|subsys_initcall|fs_initcall|rootfs_initcall|device_initcall|late_initcall|"
    r"\w+_initcall_sync|module_\w+_driver)\s*\(\s*(\w+)\s*\)",
    re.MULTILINE,
)
EXPORT_RE = re.compile(
    r"^(EXPORT_(?:SYMBOL(?:_GPL|_NS|_NS_GPL|_GPL_FUTURE|_FOR_TESTS_ONLY)?|IPV6_MOD(?:_GPL)?|"
    r"INDIRECT_CALLABLE\w*|TRACEPOINT_SYMBOL(?:_GPL)?|PER_CPU_SYMBOL(?:_GPL)?|"
    r"STATIC_CALL(?:_TRAMP)?(?:_GPL)?))\s*\(\s*(\w+)\s*(?:,\s*([\w\"]+)\s*)?\)",
    re.MULTILINE,
)

# SNMP table -> (key prefix, /proc file). Keys match what nstat and snmp_counter.rst show.
SNMP_TABLES = {
    "snmp4_ipstats_list": ("Ip", "/proc/net/snmp"),
    "snmp4_ipextstats_list": ("IpExt", "/proc/net/netstat"),
    "snmp4_tcp_list": ("Tcp", "/proc/net/snmp"),
    "snmp4_udp_list": ("Udp", "/proc/net/snmp"),
    "snmp4_net_list": ("TcpExt", "/proc/net/netstat"),
    "mptcp_snmp_list": ("MPTcpExt", "/proc/net/netstat"),
    "snmp6_ipstats_list": ("", "/proc/net/snmp6"),
    "snmp6_icmp6_list": ("", "/proc/net/snmp6"),
    "snmp6_udp6_list": ("", "/proc/net/snmp6"),
    "snmp6_udplite6_list": ("", "/proc/net/snmp6"),
    "xfrm_mib_list": ("", "/proc/net/xfrm_stat"),
    "tls_mib_list": ("", "/proc/net/tls_stat"),
    "sctp_snmp_list": ("", "/proc/net/sctp/snmp"),
}
# Counters that net/ipv4/proc.c prints from fixed strings rather than an SNMP_MIB_ITEM table.
ICMP_FIXED_COUNTERS = {
    "IcmpInMsgs": "ICMP_MIB_INMSGS", "IcmpInErrors": "ICMP_MIB_INERRORS",
    "IcmpInCsumErrors": "ICMP_MIB_CSUMERRORS", "IcmpOutMsgs": "ICMP_MIB_OUTMSGS",
    "IcmpOutErrors": "ICMP_MIB_OUTERRORS", "IcmpOutRateLimitGlobal": "ICMP_MIB_RATELIMITGLOBAL",
    "IcmpOutRateLimitHost": "ICMP_MIB_RATELIMITHOST",
}
SNMP_ITEM_RE = r"SNMP_MIB_ITEM"


class RegistryBuilder:
    def __init__(self, code: dict[str, str], symbols: SymbolIndex, kconfig_paths: list[str], makefile_paths: list[str]):
        self.code = code
        self.symbols = symbols
        self.entries: dict[str, RegistryEntry] = {}
        self.uses: list[RegistryUse] = []
        self.kconfig_paths = kconfig_paths
        self.makefile_paths = makefile_paths
        self.file_config: dict[str, str] = {}
        self.stripped: dict[str, str] = {}
        self.line_index: dict[str, LineIndex] = {}
        self.string_macros: dict[str, str] = {}
        self.map_type_ops: dict[str, str] = {}
        self.prog_type_names: dict[str, str] = {}
        self.genl_commands: dict[str, list[dict]] = {}  # command constant -> handlers
        for path, text in code.items():
            if path.endswith((".c", ".h")):
                stripped = strip_comments(text)
                self.stripped[path] = stripped
                self.line_index[path] = LineIndex(stripped)
        for symbol in symbols.symbols:
            if symbol.kind == "macro":
                value = re.match(r'#define\s+\w+\s+("(?:\\.|[^"\\])*")\s*$', symbol.signature)
                if value:
                    self.string_macros.setdefault(symbol.name, unquote(value.group(1)) or "")

    # ---- helpers ----

    def add(self, entry: RegistryEntry) -> RegistryEntry:
        entry_id = f"{entry.type}/{entry.key}"
        if entry_id in self.entries:
            suffix = entry.path or "dup"
            entry.key = f"{entry.key}@{suffix}"
            entry_id = f"{entry.type}/{entry.key}"
            counter = 2
            while entry_id in self.entries:
                entry_id = f"{entry.type}/{entry.key}#{counter}"
                counter += 1
            entry.key = entry_id[len(entry.type) + 1 :]
        entry.entry_id = entry_id
        self.entries[entry_id] = entry
        return entry

    def use(self, entry: RegistryEntry, path: str, line: int, use_kind: str, symbol_id: str | None = None) -> None:
        if symbol_id is None:
            enclosing = self.symbols.enclosing(path, line)
            symbol_id = enclosing.symbol_id if enclosing else None
        self.uses.append(RegistryUse(entry.entry_id, path, line, symbol_id, use_kind))

    def function_id(self, expression, path: str) -> str | None:
        if not isinstance(expression, str):
            return None
        name = bare_identifier(expression)
        symbol = self.symbols.resolve(name, ("function",), prefer_path=path)
        return symbol.symbol_id if symbol else None

    def string_value(self, expression: str) -> str | None:
        expression = expression.strip()
        literal = unquote(expression)
        if literal is not None:
            return literal
        return self.string_macros.get(expression)

    def initializer(self, symbol: SymbolRow):
        return initializer_of(self.symbols.source_slice(self.code, symbol))

    def struct_instances(self, struct_types: set[str]) -> list[SymbolRow]:
        return [
            s for s in self.symbols.symbols
            if s.kind in ("global", "ops_instance") and s.struct_type in struct_types and s.has_initializer
        ]

    def elements(self, symbol: SymbolRow) -> list:
        """Initializer of an instance as a list of element dicts (a single struct -> [dict])."""
        data = self.initializer(symbol)
        if isinstance(data, dict):
            if data and all(k.startswith("[") for k in data if k != "_positional"):
                items = [dict(v, _index=k.strip("[]")) if isinstance(v, dict) else {"_value": v, "_index": k.strip("[]")}
                         for k, v in data.items() if k != "_positional"]
                return items
            return [data]
        if isinstance(data, list):
            return [e for e in data if isinstance(e, (dict, list))]
        return []

    # ---- ops tables ----

    def build_ops(self) -> None:
        for symbol in self.symbols.symbols:
            if symbol.kind != "global" or not symbol.struct_type or not symbol.has_initializer:
                continue
            data = self.initializer(symbol)
            elements = data if isinstance(data, list) else [data]
            if isinstance(data, dict) and data and all(k.startswith("[") for k in data if k != "_positional"):
                elements = [v for k, v in data.items() if k != "_positional"]
            is_array = isinstance(data, list) or elements is not data and len(elements) != 1 or "[" in symbol.signature
            members: dict[str, str] = {}
            raw_members: dict[str, str] = {}
            element_members = []
            for element in elements[:MAX_ARRAY_ELEMENTS]:
                if not isinstance(element, dict):
                    continue
                resolved_here = {}
                for member, value in element.items():
                    if not isinstance(value, str) or member.startswith("_"):
                        continue
                    function_id = self.function_id(value, symbol.path)
                    if function_id:
                        resolved_here[member] = function_id
                    elif not is_array and len(value) <= 80:
                        raw_members[member] = " ".join(value.split())
                if is_array:
                    if resolved_here:
                        element_members.append(resolved_here)
                else:
                    members.update(resolved_here)
            has_functions = bool(members or element_members)
            known_type = symbol.struct_type in OPS_STRUCT_TYPES or symbol.struct_type.endswith(OPS_SUFFIXES)
            if not has_functions and not known_type:
                continue
            if symbol.struct_type == "ctl_table":
                continue  # sysctl tables have their own registry
            symbol.kind = "ops_instance"
            attrs = {"struct_type": symbol.struct_type, "members": members}
            if is_array:
                attrs["is_array"] = True
                attrs["elements"] = len(elements)
                attrs["element_members"] = element_members[:60]
            else:
                attrs["other_members"] = dict(list(raw_members.items())[:24])
            entry = self.add(
                RegistryEntry(
                    type="ops", key=f"{symbol.struct_type}/{symbol.name}", symbol_id=symbol.symbol_id,
                    path=symbol.path, line=symbol.name_line, attrs=attrs, aliases=[symbol.name],
                    text=f"{symbol.struct_type} {symbol.name} " + " ".join(members),
                )
            )
            seen = set()
            for group in [members] + element_members:
                for member, function_id in group.items():
                    if (member, function_id) not in seen:
                        seen.add((member, function_id))
                        self.uses.append(RegistryUse(entry.entry_id, symbol.path, symbol.name_line, function_id, f"member:{member}"))

    # ---- registrations ----

    def _handler_attrs(self, doit: str | None, dumpit: str | None, path: str) -> dict:
        attrs = {}
        for role, expression in (("doit", doit), ("dumpit", dumpit)):
            if not expression or expression.strip() in ("NULL", "0"):
                continue
            function_id = self.function_id(expression, path)
            attrs[role] = function_id or expression.strip()
            attrs[f"{role}_resolved"] = function_id is not None
        return attrs

    def _add_rtnl(self, path: str, line: int, family: str, msg_type: str, doit, dumpit, flags, via: str) -> None:
        family = family.strip() or "PF_UNSPEC"
        msg_type = msg_type.strip()
        if not re.fullmatch(r"[A-Z0-9_]+", msg_type):
            return
        key = f"rtnl/{msg_type}/{family}"
        handlers = self._handler_attrs(doit, dumpit, path)
        entry = self.entries.get(f"registration/{key}")
        if entry is None:
            entry = self.add(
                RegistryEntry(
                    type="registration", key=key, path=path, line=line,
                    attrs={"mechanism": "rtnl", "family": family, "msg_type": msg_type,
                           "flags": " ".join((flags or "").split()) or None, "registered_with": via},
                    aliases=[msg_type, f"rtnl/{msg_type}"],
                    text=f"rtnl {msg_type} {family}",
                )
            )
        entry.attrs.update(handlers)
        first = handlers.get("doit") if handlers.get("doit_resolved") else handlers.get("dumpit") if handlers.get("dumpit_resolved") else None
        if entry.symbol_id is None and first:
            entry.symbol_id = first
        entry.text += " " + " ".join(str(v) for k, v in handlers.items() if not k.endswith("_resolved"))
        self.use(entry, path, line, "register_call")

    def build_rtnl(self) -> None:
        for path, text in self.stripped.items():
            if "rtnl_register" not in text and "rtnl_msg_handler" not in text:
                continue
            for call in find_calls(text, r"rtnl_register(?:_module)?", self.line_index[path]):
                args = call.args
                if call.name == "rtnl_register_module":
                    args = args[1:]
                if len(args) < 4 or not re.fullmatch(r"[A-Z0-9_]+", args[1].strip()):
                    continue  # the definition or a prototype
                self._add_rtnl(path, call.line, args[0], args[1], args[2], args[3], args[4] if len(args) > 4 else None, call.name)
        for symbol in self.struct_instances({"rtnl_msg_handler"}):
            for element in self.elements(symbol):
                if isinstance(element, list):
                    padded = [e if isinstance(e, str) else "" for e in element] + [""] * 6
                    owner, family, msg_type, doit, dumpit, flags = padded[:6]
                else:
                    family, msg_type = str(element.get("protocol", "")), str(element.get("msgtype", ""))
                    doit, dumpit, flags = element.get("doit"), element.get("dumpit"), element.get("flags")
                self._add_rtnl(symbol.path, symbol.name_line, family, msg_type, doit, dumpit,
                               flags if isinstance(flags, str) else None, f"rtnl_register_many({symbol.name})")

    def build_genl(self) -> None:
        # every genl ops table: command constant -> handlers
        for symbol in self.struct_instances({"genl_ops", "genl_small_ops", "genl_split_ops"}):
            for element in self.elements(symbol):
                if not isinstance(element, dict) or not isinstance(element.get("cmd"), str):
                    continue
                handlers = self._handler_attrs(element.get("doit"), element.get("dumpit"), symbol.path)
                if isinstance(element.get("policy"), str):
                    handlers["policy"] = element["policy"]
                handlers.update({"cmd": element["cmd"].strip(), "ops_table": symbol.symbol_id})
                self.genl_commands.setdefault(handlers["cmd"], []).append(handlers)
        for path, text in self.stripped.items():
            if "genl_register_family" not in text:
                continue
            for call in find_calls(text, r"genl_register_family", self.line_index[path]):
                name = bare_identifier(call.args[0]) if call.args else None
                symbol = self.symbols.resolve(name, ("global", "ops_instance"), prefer_path=path)
                if symbol is None or symbol.struct_type != "genl_family":
                    continue
                data = self.initializer(symbol)
                if not isinstance(data, dict):
                    continue
                raw_name = data.get("name", "")
                family_name = self.string_value(raw_name) if isinstance(raw_name, str) else None
                commands = []
                for member in ("ops", "small_ops", "split_ops"):
                    table = self.symbols.resolve(bare_identifier(data.get(member, "")) if isinstance(data.get(member), str) else None,
                                                 ("global", "ops_instance"), prefer_path=symbol.path)
                    if table is None:
                        continue
                    for element in self.elements(table):
                        if isinstance(element, dict) and isinstance(element.get("cmd"), str):
                            commands.append({"cmd": element["cmd"].strip(), **self._handler_attrs(element.get("doit"), element.get("dumpit"), table.path)})
                entry = self.add(
                    RegistryEntry(
                        type="registration", key=f"genl/{family_name or symbol.name}",
                        symbol_id=symbol.symbol_id, path=path, line=call.line, resolved=family_name is not None,
                        attrs={"mechanism": "genl", "family": family_name, "family_symbol": symbol.name,
                               "name_expression": raw_name if isinstance(raw_name, str) else None,
                               "commands": commands[:200], "command_count": len(commands)},
                        aliases=[symbol.name] + ([family_name] if family_name else []),
                        text=f"genl generic netlink family {family_name} {symbol.name} " + " ".join(c["cmd"] for c in commands),
                    )
                )
                self.use(entry, path, call.line, "register_call")

    def build_nfnl(self) -> None:
        for symbol in self.struct_instances({"nfnl_callback"}):
            for element in self.elements(symbol):
                if not isinstance(element, dict) or "_index" not in element:
                    continue
                message = element["_index"]
                call = element.get("call")
                function_id = self.function_id(call, symbol.path)
                entry = self.add(
                    RegistryEntry(
                        type="registration", key=f"nfnl/{message}", symbol_id=function_id,
                        path=symbol.path, line=symbol.name_line, resolved=function_id is not None,
                        attrs={"mechanism": "nfnl", "msg_type": message, "call": function_id or call,
                               "callback_type": element.get("type") if isinstance(element.get("type"), str) else None,
                               "policy": element.get("policy") if isinstance(element.get("policy"), str) else None,
                               "table": symbol.symbol_id},
                        aliases=[message],
                        text=f"nfnetlink {message} {call}",
                    )
                )
                self.use(entry, symbol.path, symbol.name_line, "register_call", symbol.symbol_id)

    def build_netfilter_hooks(self) -> None:
        by_table: dict[str, list[RegistryEntry]] = {}
        for symbol in self.struct_instances({"nf_hook_ops"}):
            for element in self.elements(symbol):
                if not isinstance(element, dict) or not isinstance(element.get("hook"), str):
                    continue
                hook = bare_identifier(element["hook"]) or element["hook"].strip()
                function_id = self.function_id(element["hook"], symbol.path)
                pf = element.get("pf", "").strip() if isinstance(element.get("pf"), str) else None
                hooknum = element.get("hooknum", "").strip() if isinstance(element.get("hooknum"), str) else None
                priority = " ".join(element["priority"].split()) if isinstance(element.get("priority"), str) else None
                entry = self.add(
                    RegistryEntry(
                        type="registration", key="/".join(p for p in ("netfilter", hook, pf, hooknum) if p),
                        symbol_id=function_id, path=symbol.path, line=symbol.name_line,
                        resolved=function_id is not None,
                        attrs={"mechanism": "netfilter", "hook": function_id or hook, "protocol": pf,
                               "hooknum": hooknum, "priority": priority, "ops_table": symbol.symbol_id},
                        aliases=[hook, f"netfilter/{hook}"],
                        text=f"netfilter hook {hook} {pf} {hooknum} {priority}",
                    )
                )
                by_table.setdefault(symbol.name, []).append(entry)
        for path, text in self.stripped.items():
            if "nf_register_net_hook" not in text:
                continue
            for call in find_calls(text, r"nf_register_net_hooks?", self.line_index[path]):
                table = bare_identifier(call.args[1]) if len(call.args) > 1 else None
                for entry in by_table.get(table or "", []):
                    self.use(entry, path, call.line, "register_call")

    def build_pernet(self) -> None:
        for path, text in self.stripped.items():
            if "register_pernet_" not in text:
                continue
            for call in find_calls(text, r"register_pernet_(?:subsys|device)", self.line_index[path]):
                name = bare_identifier(call.args[0]) if call.args else None
                symbol = self.symbols.resolve(name, ("global", "ops_instance"), prefer_path=path)
                if not name or call.line == (symbol.name_line if symbol else -1):
                    continue
                if self.symbols.enclosing(path, call.line) is None:
                    continue  # a prototype
                attrs = {"mechanism": "pernet", "kind": call.name.rsplit("_", 1)[-1], "ops": name}
                if symbol is not None and symbol.struct_type == "pernet_operations":
                    data = self.initializer(symbol)
                    if isinstance(data, dict):
                        for member in ("init", "pre_exit", "exit", "exit_batch", "exit_batch_rtnl"):
                            if isinstance(data.get(member), str):
                                attrs[member] = self.function_id(data[member], symbol.path) or data[member].strip()
                        for member in ("id", "size"):
                            if isinstance(data.get(member), str):
                                attrs[member] = " ".join(data[member].split())
                elif symbol is None:
                    continue
                entry = self.entries.get(f"registration/pernet/{name}")
                if entry is None or entry.path != path:
                    entry = self.add(
                        RegistryEntry(
                            type="registration", key=f"pernet/{name}",
                            symbol_id=symbol.symbol_id if symbol else None, path=path, line=call.line,
                            attrs=attrs, aliases=[name], text=f"pernet network namespace {name} {attrs['kind']}",
                        )
                    )
                self.use(entry, path, call.line, "register_call")

    def build_initcalls(self) -> None:
        for path, text in self.stripped.items():
            for match in INITCALL_RE.finditer(text):
                level, name = match.groups()
                line = self.line_index[path].line(match.start())
                symbol = self.symbols.resolve(name, None, prefer_path=path)
                if symbol is not None and symbol.path != path:
                    symbol = None
                self.add(
                    RegistryEntry(
                        type="registration", key=f"initcall/{name}",
                        symbol_id=symbol.symbol_id if symbol else None, path=path, line=line,
                        resolved=symbol is not None,
                        attrs={"mechanism": "initcall", "level": level, "function": name},
                        aliases=[name], text=f"initcall {level} {name}",
                    )
                )

    # ---- sysctls ----

    def _sysctl_table_paths(self, path: str, text: str, tables: dict[str, SymbolRow]):
        """Paths from the register calls in one file.

        Returns ({table name -> (dotted path, is_template)}, [(dotted, template, function)])
        where the second list holds calls whose table comes from a function defined elsewhere.
        """
        found: dict[str, tuple[str, bool]] = {}
        deferred: list[tuple[str, bool, str]] = []
        literal_paths = []
        calls = find_calls(text, r"register_net_sysctl(?:_sz)?|register_sysctl(?:_sz|_init)?", self.line_index[path])
        for call in calls:
            args = call.args[1:] if call.name.startswith("register_net_sysctl") else call.args
            if len(args) < 2:
                continue
            enclosing = self.symbols.enclosing(path, call.line)
            if enclosing is None or enclosing.kind != "function":
                continue
            body = strip_comments(self.symbols.source_slice(self.code, enclosing))
            sysctl_path = self.string_value(args[0])
            template = False
            if sysctl_path is None:
                formats = re.findall(r'snprintf\s*\([^;]*?"(net/[^"]*%s[^"]*)"', body, re.DOTALL)
                if not formats:
                    continue
                sysctl_path = formats[0]
                if "/neigh/" in sysctl_path:
                    sysctl_path = sysctl_path.replace("%s", "<proto>", 1)
                sysctl_path = sysctl_path.replace("%s", "<dev>")
                template = True
            dotted = sysctl_path.strip("/").replace("/", ".")
            literal_paths.append((dotted, template))
            direct = bare_identifier(args[1])
            candidates: list[str] = []
            producers: list[str] = []
            if direct in tables:
                candidates = [direct]
            elif direct:
                # a local variable: follow what the function assigns to it
                for value in re.findall(rf"\b{re.escape(direct)}\s*=\s*([^;]+);", body):
                    named = [t for t in tables if re.search(rf"\b{re.escape(t)}\b", value)]
                    candidates += [t for t in named if t not in candidates]
                    producer = re.match(r"\s*(?:\([^)]*\)\s*)?(\w+)\s*\(", value)
                    if not named and producer and producer.group(1) not in ("kmemdup", "kmalloc", "kzalloc", "kcalloc"):
                        producers.append(producer.group(1))
            if not candidates and not producers:
                candidates = [t for t in tables if re.search(rf"\b{re.escape(t)}\b", body)]
            for table in candidates:
                found.setdefault(table, (dotted, template))
            deferred += [(dotted, template, producer) for producer in producers]
        distinct = sorted(set(literal_paths))
        if len(distinct) == 1 and not deferred:
            for table in tables:
                found.setdefault(table, distinct[0])
        return found, deferred

    def build_sysctls(self) -> None:
        entry_re = re.compile(
            r'\.procname\s*=\s*("(?:\\.|[^"\\])*"|[A-Z_][A-Z0-9_]*)|\b(\w*SYSCTL\w*_ENTRY\w*)\s*\('
        )
        all_hits = []
        table_paths: dict[str, tuple[str, bool]] = {}  # table symbol_id -> path
        deferred_all: list[tuple[str, bool, str]] = []
        for path, text in self.stripped.items():
            if "procname" not in text and "SYSCTL" not in text and "register_net_sysctl" not in text:
                continue
            lines = self.line_index[path]
            hits = []
            for match in entry_re.finditer(text):
                line = lines.line(match.start())
                table = self.symbols.enclosing(path, line)
                if table is None or table.kind not in ("global", "ops_instance"):
                    continue
                if match.group(1):
                    procname = self.string_value(match.group(1))
                    # the innermost brace block around this entry holds its other fields
                    open_offset = text.rfind("{", 0, match.start())
                    close = matching_close(text, open_offset) if open_offset != -1 else -1
                    fields = parse_initializer(text[open_offset : close + 1]) if close != -1 else {}
                    hits.append((path, line, table, procname, fields if isinstance(fields, dict) else {}, None))
                else:
                    close = matching_close(text, match.end() - 1)
                    args = split_top_level(text[match.end() : close]) if close != -1 else []
                    procname = next((unquote(a) for a in args if unquote(a) is not None), None)
                    hits.append((path, line, table, procname, {"macro_args": args}, match.group(2)))
            tables = {table.name: table for _, _, table, _, _, _ in hits}
            found, deferred = self._sysctl_table_paths(path, text, tables)
            for name, located in found.items():
                table_paths.setdefault(tables[name].symbol_id, located)
            deferred_all += deferred
            all_hits += hits
        # tables handed over by an init function in another file
        tables_by_name: dict[str, list[SymbolRow]] = {}
        for _, _, table, _, _, _ in all_hits:
            if table not in tables_by_name.setdefault(table.name, []):
                tables_by_name[table.name].append(table)
        for dotted, template, producer in deferred_all:
            function = self.symbols.resolve(producer, ("function",))
            if function is None:
                continue
            body = strip_comments(self.symbols.source_slice(self.code, function))
            for name, rows in tables_by_name.items():
                if re.search(rf"\b{re.escape(name)}\b", body):
                    for table in rows:
                        if table.path == function.path:
                            table_paths.setdefault(table.symbol_id, (dotted, template))
        for path, line, table, procname, fields, macro in all_hits:
            if not procname:
                continue
            located = table_paths.get(table.symbol_id)
            dotted, template = located if located else (None, False)
            attrs = {"table": table.symbol_id, "procname": procname, "template": template or None}
            if macro:
                attrs["macro"] = macro
                attrs["macro_args"] = fields.get("macro_args")
            else:
                for member in ("data", "mode", "maxlen"):
                    if isinstance(fields.get(member), str):
                        attrs[member] = " ".join(fields[member].split())
                handler = fields.get("proc_handler")
                if isinstance(handler, str):
                    attrs["proc_handler"] = self.function_id(handler, path) or handler.strip()
                for member, name in (("extra1", "min"), ("extra2", "max")):
                    if isinstance(fields.get(member), str):
                        attrs[name] = " ".join(fields[member].split())
            key = f"{dotted}.{procname}" if dotted else f"?.{procname}"
            self.add(
                RegistryEntry(
                    type="sysctl", key=key, symbol_id=table.symbol_id, path=path, line=line,
                    resolved=dotted is not None, attrs=attrs, aliases=[procname],
                    text=f"sysctl {key} {procname} {attrs.get('data', '')}",
                )
            )

    # ---- SNMP counters ----

    def build_snmp(self) -> None:
        constants: dict[str, list[RegistryEntry]] = {}
        definition_sites: set[tuple[str, int]] = set()
        for path, text in self.stripped.items():
            if "SNMP_MIB_ITEM" not in text:
                continue
            for call in find_calls(text, SNMP_ITEM_RE, self.line_index[path]):
                if len(call.args) != 2:
                    continue
                name = unquote(call.args[0])
                constant = call.args[1].strip()
                table = self.symbols.enclosing(path, call.line)
                if name is None or table is None or table.kind not in ("global", "ops_instance"):
                    continue
                prefix, proc_file = SNMP_TABLES.get(table.name, ("", None))
                entry = self.add(
                    RegistryEntry(
                        type="snmp", key=prefix + name, symbol_id=table.symbol_id, path=path, line=call.line,
                        attrs={"mib": constant, "mib_table": table.name, "proc_file": proc_file, "name": name},
                        aliases=[name, constant] + (["UdpLite" + name] if table.name == "snmp4_udp_list" else []),
                        text=f"snmp counter {prefix}{name} {name} {constant}",
                    )
                )
                constants.setdefault(constant, []).append(entry)
                definition_sites.add((path, call.line))
        proc = "net/ipv4/proc.c"
        if proc in self.stripped:
            text = self.stripped[proc]
            table = self.symbols.resolve("icmpmibmap", None, prefer_path=proc)
            for name, constant in ICMP_FIXED_COUNTERS.items():
                short = name[len("Icmp"):]
                offset = self.code[proc].find(short)
                if offset == -1:
                    continue
                entry = self.add(
                    RegistryEntry(
                        type="snmp", key=name, path=proc, line=self.line_index[proc].line(offset),
                        attrs={"mib": constant, "mib_table": "icmp_put (fixed header)", "proc_file": "/proc/net/snmp", "name": short},
                        aliases=[short, constant], text=f"snmp counter {name} {constant}",
                    )
                )
                constants.setdefault(constant, []).append(entry)
            if table is not None:
                data = self.initializer(table)
                for element in data if isinstance(data, list) else []:
                    if not isinstance(element, list) or len(element) < 2:
                        continue
                    strings = [e for e in element if isinstance(e, str)]
                    label = next((unquote(e) for e in strings if unquote(e) is not None), None)
                    icmp_type = next((e.strip() for e in strings if unquote(e) is None), None)
                    if not label or not icmp_type or icmp_type in ("0", "NULL"):
                        continue
                    for direction in ("In", "Out"):
                        self.add(
                            RegistryEntry(
                                type="snmp", key=f"Icmp{direction}{label}", symbol_id=table.symbol_id,
                                path=proc, line=table.name_line,
                                attrs={"mib": f"ICMPMSG_MIB ({icmp_type}, {direction.lower()})", "mib_table": "icmpmibmap",
                                       "proc_file": "/proc/net/snmp", "name": f"{direction}{label}", "icmp_type": icmp_type},
                                aliases=[f"{direction}{label}"], text=f"snmp counter Icmp{direction}{label} {icmp_type}",
                            )
                        )
        if not constants:
            return
        pattern = re.compile(r"\b[A-Z0-9]+_MIB_[A-Z0-9_]+\b")
        for path, text in self.stripped.items():
            if "_MIB_" not in text:
                continue
            for match in pattern.finditer(text):
                entries = constants.get(match.group(0))
                if not entries:
                    continue
                line = self.line_index[path].line(match.start())
                if (path, line) in definition_sites:
                    continue
                enclosing = self.symbols.enclosing(path, line)
                if enclosing is None or enclosing.kind != "function":
                    continue  # the enum definition, or another table
                for entry in entries:
                    self.uses.append(RegistryUse(entry.entry_id, path, line, enclosing.symbol_id, "increment"))

    # ---- tracepoints ----

    def build_tracepoints(self) -> None:
        events: dict[str, RegistryEntry] = {}
        for path, text in self.stripped.items():
            if not path.startswith("include/trace/events/"):
                continue
            lines = self.line_index[path]
            system = re.search(r"#define\s+TRACE_SYSTEM\s+(\w+)", text)
            classes: dict[str, dict] = {}
            calls = find_calls(
                text, r"TRACE_EVENT(?:_CONDITION|_FN|_FN_COND)?|DECLARE_EVENT_CLASS|DEFINE_EVENT(?:_PRINT|_CONDITION|_FN)?|DECLARE_TRACE", lines
            )
            for call in calls:
                if not call.args or not re.fullmatch(r"\w+", call.args[0]):
                    continue
                body = text[call.offset : call.end]
                line_start = text.rfind("\n", 0, call.offset) + 1
                if text[line_start:call.offset].lstrip().startswith("#"):
                    continue  # a wrapper macro definition, not an event
                proto = re.search(r"TP_PROTO\s*\(", body)
                proto_text = None
                if proto:
                    close = matching_close(body, proto.end() - 1)
                    proto_text = " ".join(body[proto.end() : close].split()) if close != -1 else None
                fields = []
                entry_block = re.search(r"TP_STRUCT__entry\s*\(", body)
                if entry_block:
                    close = matching_close(body, entry_block.end() - 1)
                    block = body[entry_block.end() : close] if close != -1 else ""
                    for field in find_calls(block, r"__field(?:_struct)?|__array|__string|__dynamic_array|__sockaddr|__bitmask|__rel_\w+|__field_hex"):
                        args = [" ".join(a.split()) for a in field.args]
                        if field.name in ("__string", "__sockaddr", "__bitmask") and args:
                            fields.append({"name": args[0], "type": field.name.strip("_")})
                        elif len(args) >= 2:
                            fields.append({"name": args[1], "type": args[0]})
                end_line = lines.line(call.end)
                if call.name == "DECLARE_EVENT_CLASS":
                    classes[call.args[0]] = {"fields": fields, "proto": proto_text, "line": call.line}
                    continue
                if call.name.startswith("DEFINE_EVENT"):
                    if len(call.args) < 2 or not re.fullmatch(r"\w+", call.args[1]):
                        continue
                    event, event_class = call.args[1], call.args[0]
                    inherited = classes.get(event_class, {})
                    fields = inherited.get("fields", [])
                    proto_text = proto_text or inherited.get("proto")
                else:
                    event, event_class = call.args[0], None
                entry = self.add(
                    RegistryEntry(
                        type="tracepoint", key=event, path=path, line=call.line,
                        attrs={"header": path, "system": system.group(1) if system else None,
                               "class": event_class, "proto": proto_text, "fields": fields,
                               "end_line": end_line, "macro": call.name,
                               "class_line": classes.get(event_class, {}).get("line") if event_class else None},
                        aliases=[f"trace_{event}"],
                        text=f"tracepoint trace event {event} {event_class or ''} " + " ".join(f["name"] for f in fields),
                    )
                )
                events.setdefault(event, entry)
        if not events:
            return
        pattern = re.compile(r"\btrace_(\w+?)(_enabled|_rcuidle)?\s*\(")
        for path, text in self.stripped.items():
            if "trace_" not in text or path.startswith("include/trace/events/"):
                continue
            for match in pattern.finditer(text):
                entry = events.get(match.group(1)) or events.get(match.group(1) + (match.group(2) or ""))
                if entry is None:
                    continue
                line = self.line_index[path].line(match.start())
                enclosing = self.symbols.enclosing(path, line)
                if enclosing is None:
                    continue
                self.uses.append(RegistryUse(entry.entry_id, path, line, enclosing.symbol_id, "trace_call"))

    # ---- exports ----

    def build_exports(self) -> None:
        for path, text in self.stripped.items():
            if "EXPORT_" not in text:
                continue
            for match in EXPORT_RE.finditer(text):
                macro, name, namespace = match.groups()
                line = self.line_index[path].line(match.start())
                local = [s for s in self.symbols.find(name, None, prefer_path=path) if s.path == path]
                local.sort(key=lambda s: (s.kind not in ("function", "global", "ops_instance"), s.start_line))
                symbol = local[0] if local else None
                if symbol is not None:
                    symbol.is_exported = True
                if macro.startswith("EXPORT_TRACEPOINT"):
                    name_key = f"__tracepoint_{name}"
                else:
                    name_key = name
                self.add(
                    RegistryEntry(
                        type="export", key=name_key, symbol_id=symbol.symbol_id if symbol else None,
                        path=path, line=line, resolved=symbol is not None,
                        attrs={"license": "GPL" if "GPL" in macro else "any", "macro": macro,
                               "namespace": namespace.strip('"') if namespace and "NS" in macro else None},
                        text=f"export {name}",
                    )
                )

    # ---- Kconfig ----

    def build_kconfig(self) -> None:
        makefiles = {p: self.code[p] for p in self.makefile_paths}
        sources = {p for p in self.code if p.endswith(".c")}
        self.file_config, by_config = buildsys.file_configs(makefiles, sources)
        seen: dict[str, RegistryEntry] = {}
        for path in self.kconfig_paths:
            for option in buildsys.parse_kconfig(path, self.code[path]):
                if option.name in seen:
                    seen[option.name].attrs.setdefault("also_defined_at", []).append(f"{path}:{option.line}")
                    continue
                entry = self.add(
                    RegistryEntry(
                        type="kconfig", key=option.name, path=path, line=option.line,
                        attrs={"value_type": option.value_type, "prompt": option.prompt,
                               "default": option.defaults or None, "depends_on": option.depends_on or None,
                               "selects": option.selects or None, "implies": option.implies or None,
                               "help": option.help[:2500] or None, "end_line": option.end_line,
                               "files": sorted(by_config.get(option.name, []))},
                        aliases=[option.name[len("CONFIG_"):]],
                        text=f"{option.name} {option.prompt or ''} {option.help[:800]}",
                    )
                )
                seen[option.name] = entry
        for config, files in by_config.items():
            if config not in seen:
                entry = self.add(
                    RegistryEntry(
                        type="kconfig", key=config, resolved=False,
                        attrs={"files": sorted(files), "note": "defined in a Kconfig file outside the v1 scope"},
                        aliases=[config[len("CONFIG_"):]], text=config,
                    )
                )
                seen[config] = entry

    # ---- BPF helpers ----

    def build_bpf_helpers(self) -> None:
        header = "include/uapi/linux/bpf.h"
        text = self.code.get(header)
        if text is None:
            return
        lines = text.split("\n")
        start = next((i for i, l in enumerate(lines) if "Start of BPF helper function descriptions" in l), None)
        if start is None:
            return
        end = next((i for i in range(start, len(lines)) if lines[i].strip() == "*/"), len(lines))
        helpers: dict[str, dict] = {}
        current = None
        section = None
        for index in range(start + 1, end):
            line = lines[index]
            signature = re.match(r"^ \* (\S[^\t]*\b(bpf_\w+)\s*\(.*\))\s*$", line)
            if signature and not line.startswith(" * \t"):
                current = {"signature": signature.group(1), "line": index + 1, "end_line": index + 1,
                           "Description": [], "Return": []}
                helpers[signature.group(2)] = current
                section = None
                continue
            if current is None:
                continue
            body = line[3:] if line.startswith(" * ") else line[2:] if line.startswith(" *") else line
            label = body.strip()
            if body.startswith("\t") and not body.startswith("\t\t") and label in ("Description", "Return"):
                section = label
            elif section and body.startswith("\t\t"):
                current[section].append(body.strip())
                current["end_line"] = index + 1
            elif section and not label:
                current[section].append("")
        func_ids = {m.group(1): int(m.group(2)) for m in re.finditer(r"^\s*FN\((\w+),\s*(\d+),", text, re.MULTILINE)}
        types_text = self.stripped.get("include/linux/bpf_types.h", "")
        for match in re.finditer(r"BPF_PROG_TYPE\(\s*(BPF_PROG_TYPE_\w+)\s*,\s*(\w+)", types_text):
            self.prog_type_names[match.group(2)] = match.group(1)
        for match in re.finditer(r"BPF_MAP_TYPE\(\s*(BPF_MAP_TYPE_\w+)\s*,\s*(\w+)", types_text):
            self.map_type_ops[match.group(1)] = match.group(2)

        # helper -> the protos returned for it in *_func_proto() switch statements
        proto_sites: dict[str, list[tuple[str, str, int, str | None]]] = {}
        case_re = re.compile(r"case\s+BPF_FUNC_(\w+)\s*:")
        for path, stripped in self.stripped.items():
            if "BPF_FUNC_" not in stripped:
                continue
            matches = list(case_re.finditer(stripped))
            for position, match in enumerate(matches):
                tail_end = stripped.find(";", match.end())
                # consecutive case labels share the statement that follows the last of them
                probe = position
                while probe + 1 < len(matches) and not stripped[matches[probe].end() : matches[probe + 1].start()].strip():
                    probe += 1
                statement_start = matches[probe].end()
                statement_end = stripped.find("case ", statement_start)
                default_at = stripped.find("default:", statement_start)
                bounds = [b for b in (statement_end, default_at) if b != -1]
                block = stripped[statement_start : min(bounds) if bounds else tail_end + 1]
                line = self.line_index[path].line(match.start())
                enclosing = self.symbols.enclosing(path, line)
                for proto in dict.fromkeys(re.findall(r"&\s*(\w+_proto\w*)", block)):
                    proto_sites.setdefault(match.group(1), []).append(
                        (proto, path, line, enclosing.name if enclosing else None)
                    )
        # *_func_proto function -> program types, through bpf_verifier_ops instances
        proto_function_types: dict[str, set[str]] = {}
        for symbol in self.struct_instances({"bpf_verifier_ops"}):
            data = self.initializer(symbol)
            getter = bare_identifier(data.get("get_func_proto", "")) if isinstance(data, dict) and isinstance(data.get("get_func_proto"), str) else None
            prog_type = self.prog_type_names.get(symbol.name[: -len("_verifier_ops")]) if symbol.name.endswith("_verifier_ops") else None
            if getter and prog_type:
                proto_function_types.setdefault(getter, set()).add(prog_type)

        for name, info in helpers.items():
            short = name[len("bpf_"):]
            implementations = []
            prog_types: set[str] = set()
            getters: set[str] = set()
            for proto, path, line, getter in proto_sites.get(short, []):
                proto_symbol = self.symbols.resolve(proto, ("global", "ops_instance"), prefer_path=path)
                implementation = None
                if proto_symbol is not None:
                    data = self.initializer(proto_symbol)
                    if isinstance(data, dict) and isinstance(data.get("func"), str):
                        implementation = self.function_id(data["func"], proto_symbol.path)
                record = {"proto": proto_symbol.symbol_id if proto_symbol else proto,
                          "impl": implementation, "selected_in": getter, "path": path, "line": line}
                if not any(r["proto"] == record["proto"] for r in implementations):
                    implementations.append(record)
                if getter:
                    getters.add(getter)
                    prog_types |= proto_function_types.get(getter, set())
            primary = implementations[0] if implementations else {}
            description = "\n".join(info["Description"]).strip()
            entry = self.add(
                RegistryEntry(
                    type="bpf_helper", key=name, path=header, line=info["line"],
                    symbol_id=primary.get("impl"),
                    resolved=bool(primary.get("impl")),
                    attrs={"signature": info["signature"], "description": description[:3000],
                           "return": " ".join(" ".join(info["Return"]).split())[:800],
                           "func_id": func_ids.get(short), "end_line": info["end_line"],
                           "impl_symbol_id": primary.get("impl"),
                           "proto_symbol_id": primary.get("proto") if implementations else None,
                           "implementations": implementations[:12],
                           "prog_types": sorted(prog_types),
                           "func_proto_functions": sorted(getters)},
                    aliases=[f"BPF_FUNC_{short}", short],
                    text=f"bpf helper {name} {info['signature']} {description[:600]}",
                )
            )
            for record in implementations:
                self.uses.append(RegistryUse(entry.entry_id, record["path"], record["line"], None, "register_call"))
                last = self.uses[-1]
                enclosing = self.symbols.enclosing(record["path"], record["line"])
                last.symbol_id = enclosing.symbol_id if enclosing else None

    def add_handler_uses(self) -> None:
        """Reverse links from a function to the entries it serves (handler, hook, init...)."""
        roles = ("doit", "dumpit", "call", "hook", "init", "exit", "pre_exit", "exit_batch", "proc_handler")
        for entry in list(self.entries.values()):
            if entry.type not in ("registration", "sysctl", "bpf_helper"):
                continue
            for role in roles:
                value = entry.attrs.get(role)
                if isinstance(value, str) and "::" in value and entry.path:
                    self.uses.append(RegistryUse(entry.entry_id, entry.path, entry.line or 0, value, f"handler:{role}"))
            for implementation in entry.attrs.get("implementations", []) if entry.type == "bpf_helper" else []:
                if implementation.get("impl"):
                    self.uses.append(RegistryUse(entry.entry_id, implementation["path"], implementation["line"], implementation["impl"], "handler:impl"))

    def build_all(self) -> None:
        self.build_ops()
        self.build_rtnl()
        self.build_genl()
        self.build_nfnl()
        self.build_netfilter_hooks()
        self.build_pernet()
        self.build_initcalls()
        self.build_sysctls()
        self.build_snmp()
        self.build_tracepoints()
        self.build_exports()
        self.build_kconfig()
        self.build_bpf_helpers()
        self.add_handler_uses()
