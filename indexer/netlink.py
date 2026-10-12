"""Netlink YAML specs (Documentation/netlink/specs) parsed into families, operations and attributes."""

from dataclasses import dataclass, field

import yaml

# Files in the v6.12 tree that are generated from a spec ("auto-generated from" header).
GENERATED_CODE = {
    "devlink": ["net/devlink/netlink_gen.c", "net/devlink/netlink_gen.h"],
    "dpll": ["drivers/dpll/dpll_nl.c", "drivers/dpll/dpll_nl.h", "include/uapi/linux/dpll.h"],
    "fou": ["net/ipv4/fou_nl.c", "net/ipv4/fou_nl.h", "include/uapi/linux/fou.h"],
    "handshake": ["net/handshake/genl.c", "net/handshake/genl.h", "include/uapi/linux/handshake.h"],
    "mptcp_pm": ["net/mptcp/mptcp_pm_gen.c", "net/mptcp/mptcp_pm_gen.h", "include/uapi/linux/mptcp_pm.h"],
    "netdev": ["net/core/netdev-genl-gen.c", "net/core/netdev-genl-gen.h", "include/uapi/linux/netdev.h"],
    "team": ["drivers/net/team/team_nl.c", "drivers/net/team/team_nl.h", "include/uapi/linux/if_team.h"],
}

# Message-constant prefix for raw (rtnetlink-style) families, keyed by spec file stem.
RAW_MESSAGE_PREFIX = {
    "rt_route": "RTM_", "rt_addr": "RTM_", "rt_link": "RTM_", "tc": "RTM_", "nftables": "NFT_MSG_",
}
# Hand-written genetlink families whose command constants do not follow <FAMILY>_CMD_<OP>.
COMMAND_PREFIX = {
    "nlctrl": "CTRL_CMD_", "ovs_datapath": "OVS_DP_CMD_", "ovs_flow": "OVS_FLOW_CMD_",
    "ovs_vport": "OVS_VPORT_CMD_", "tcp_metrics": "TCP_METRICS_CMD_", "ethtool": "ETHTOOL_MSG_",
    "devlink": "DEVLINK_CMD_", "team": "TEAM_CMD_", "fou": "FOU_CMD_", "dpll": "DPLL_CMD_",
    "handshake": "HANDSHAKE_CMD_", "mptcp_pm": "MPTCP_PM_CMD_", "netdev": "NETDEV_CMD_",
}


@dataclass
class NetlinkOp:
    family: str
    op: str
    value: str | None
    doc: str
    doc_id: str
    do_request_attrs: list[str] | None
    do_reply_attrs: list[str] | None
    dump_attrs: dict | None
    message_constant: str
    attrs: dict = field(default_factory=dict)


@dataclass
class NetlinkAttr:
    family: str
    attr_set: str
    name: str
    type: str | None
    doc: str | None
    doc_id: str
    attrs: dict = field(default_factory=dict)


@dataclass
class NetlinkFamily:
    family: str  # the spec file stem, e.g. "rt_route"
    name: str  # the family name in the spec, e.g. "rt-route"
    spec_doc_id: str
    protocol: str
    uapi_header: str | None
    generated_code: list[str]
    attrs: dict
    ops: list[NetlinkOp] = field(default_factory=list)
    attributes: list[NetlinkAttr] = field(default_factory=list)


def _constant(prefix: str, name: str) -> str:
    return (prefix + name).upper().replace("-", "_")


def _attr_list(block) -> list[str] | None:
    if not isinstance(block, dict):
        return None
    attributes = block.get("attributes")
    return list(attributes) if isinstance(attributes, list) else None


def parse_spec(doc_path: str, text: str) -> NetlinkFamily:
    data = yaml.safe_load(text)
    stem = doc_path.rsplit("/", 1)[-1][: -len(".yaml")]
    protocol = data.get("protocol", "genetlink")
    operations = data.get("operations") or {}
    op_prefix = operations.get("name-prefix")
    if stem in RAW_MESSAGE_PREFIX:
        constant_prefix = RAW_MESSAGE_PREFIX[stem]
    elif stem in COMMAND_PREFIX:
        constant_prefix = COMMAND_PREFIX[stem]
    elif op_prefix:
        constant_prefix = op_prefix
    else:
        constant_prefix = f"{data.get('c-family-name') or data['name']}-cmd-"
    family = NetlinkFamily(
        family=stem,
        name=data["name"],
        spec_doc_id=f"{doc_path}#spec",
        protocol=protocol,
        uapi_header=data.get("uapi-header") or (f"linux/{stem}.h" if protocol == "genetlink" else None),
        generated_code=GENERATED_CODE.get(stem, []),
        attrs={
            "name": data["name"],
            "doc": " ".join(str(data.get("doc", "")).split()),
            "protonum": data.get("protonum"),
            "version": data.get("version"),
            "c_family_name": data.get("c-family-name"),
            "kernel_policy": data.get("kernel-policy"),
            "mcast_groups": [g["name"] for g in (data.get("mcast-groups") or {}).get("list", [])],
            "definitions": [
                {"name": d["name"], "type": d.get("type"),
                 "doc_id": f"{doc_path}#definition/{d['name']}"}
                for d in data.get("definitions") or []
            ],
            "attribute_sets": [a["name"] for a in data.get("attribute-sets") or []],
            "message_constant_prefix": constant_prefix.upper().replace("-", "_"),
        },
    )

    for attr_set in data.get("attribute-sets") or []:
        set_name = attr_set["name"]
        for attribute in attr_set.get("attributes") or []:
            extra = {
                key: attribute[key]
                for key in ("value", "checks", "enum", "nested-attributes", "sub-message",
                            "multi-attr", "byte-order", "struct", "sub-type", "display-hint",
                            "enum-as-flags", "selector")
                if key in attribute
            }
            if "subset-of" in attr_set:
                extra["subset_of"] = attr_set["subset-of"]
            family.attributes.append(
                NetlinkAttr(
                    family=stem, attr_set=set_name, name=attribute["name"],
                    type=attribute.get("type"),
                    doc=" ".join(str(attribute["doc"]).split()) if attribute.get("doc") else None,
                    doc_id=f"{doc_path}#attr-set/{set_name}", attrs=extra,
                )
            )

    next_value = 1
    for op in operations.get("list") or []:
        name = op["name"]
        do = op.get("do") or {}
        dump = op.get("dump") or {}
        request = do.get("request") if isinstance(do, dict) else None
        reply = do.get("reply") if isinstance(do, dict) else None
        value = op.get("value")
        if value is None and isinstance(request, dict) and "value" in request:
            value = request["value"]
        if value is None and protocol != "netlink-raw" and operations.get("enum-model") != "directional":
            value = next_value
        if isinstance(value, int):
            next_value = value + 1
        kinds = [k for k in ("do", "dump", "notify", "event") if k in op]
        family.ops.append(
            NetlinkOp(
                family=stem, op=name, value=None if value is None else str(value),
                doc=" ".join(str(op.get("doc", "")).split()),
                doc_id=f"{doc_path}#op/{name}",
                do_request_attrs=_attr_list(request),
                do_reply_attrs=_attr_list(reply),
                dump_attrs=(
                    {"request": _attr_list(dump.get("request")), "reply": _attr_list(dump.get("reply"))}
                    if isinstance(dump, dict) and dump else None
                ),
                message_constant=_constant(constant_prefix, name),
                attrs={
                    "attribute_set": op.get("attribute-set"),
                    "fixed_header": op.get("fixed-header"),
                    "kinds": kinds,
                    "notify": op.get("notify"),
                    "event_attrs": _attr_list(op.get("event")),
                    "mcgrp": op.get("mcgrp"),
                    "flags": op.get("flags"),
                    "reply_value": reply.get("value") if isinstance(reply, dict) else None,
                    "value_is_derived": op.get("value") is None and not (isinstance(request, dict) and "value" in request),
                },
            )
        )
    return family
