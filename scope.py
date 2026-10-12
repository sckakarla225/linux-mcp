"""v1 scope: which documentation and source paths of torvalds/linux are indexed.

Networking internals only. Everything here is a rule over repo paths; no file is listed
because of its contents.
"""

import fnmatch

# --------------------------------------------------------------------------------------
# Documentation
# --------------------------------------------------------------------------------------

DOC_FOLDERS = ["networking", "netlink", "netlabel", "bpf", "infiniband"]
DOC_FORMATS = {".rst": "rst", ".yaml": "yaml", ".txt": "txt"}

# Documentation/networking: vendor NIC guides, per-driver devlink pages and legacy or niche
# protocol docs are left out. Framework devlink pages (devlink-*.rst) are kept.
NETWORKING_DOC_EXCLUDE = [
    "device_drivers/*",
    "mac80211_hwsim/*",
    "6lowpan.rst",
    "6pack.rst",
    "arcnet-hardware.rst",
    "arcnet.rst",
    "atm.rst",
    "ax25.rst",
    "batman-adv.rst",
    "can.rst",
    "can_ucan_protocol.rst",
    "cdc_mbim.rst",
    "eql.rst",
    "generic-hdlc.rst",
    "ieee802154.rst",
    "iso15765-2.rst",
    "j1939.rst",
    "lapb-module.rst",
    "mac80211-auth-assoc-deauth.txt",
    "mac80211-injection.rst",
    "mctp.rst",
    "nfc.rst",
    "phonet.rst",
    "plip.rst",
    "ppp_generic.rst",
    "radiotap-headers.rst",
    "regulatory.rst",
    "rxrpc.rst",
    "tipc.rst",
    "x25-iface.rst",
    "x25.rst",
]
NETWORKING_DEVLINK_KEEP = ["devlink/devlink-*.rst", "devlink/index.rst"]

NETLINK_DOC_EXCLUDE = ["specs/nfsd.yaml"]

BPF_DOC_EXCLUDE = [
    "prog_lsm.rst",
    "prog_cgroup_sysctl.rst",
    "fs_kfuncs.rst",
    "map_cgroup_storage.rst",
    "map_cgrp_storage.rst",
    "drgn.rst",
    "s390.rst",
    "bpf_devel_QA.rst",
    "bpf_design_QA.rst",
    "bpf_licensing.rst",
    "libbpf/libbpf_build.rst",
    "libbpf/libbpf_naming_convention.rst",
    "libbpf/libbpf_overview.rst",
]


def _matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def doc_format(doc_path: str) -> str | None:
    for suffix, fmt in DOC_FORMATS.items():
        if doc_path.endswith(suffix):
            return fmt
    return None


def doc_in_scope(doc_path: str) -> bool:
    """doc_path is relative to Documentation/, e.g. "networking/fib_trie.rst"."""
    folder, _, rest = doc_path.partition("/")
    if folder not in DOC_FOLDERS or not rest or doc_format(doc_path) is None:
        return False
    if folder == "networking":
        if rest.startswith("devlink/"):
            return _matches(rest, NETWORKING_DEVLINK_KEEP)
        return not _matches(rest, NETWORKING_DOC_EXCLUDE)
    if folder == "netlink":
        return not _matches(rest, NETLINK_DOC_EXCLUDE)
    if folder == "bpf":
        return not _matches(rest, BPF_DOC_EXCLUDE)
    return True


# Topic clusters. First matching pattern wins; patterns are matched against the path below
# the doc folder, without the file suffix.
NETWORKING_CLUSTERS = [
    (
        "Core datapath and device model",
        [
            "skbuff", "napi", "netdevices", "driver", "netdev-features", "page_pool", "scaling",
            "multiqueue", "checksum-offloads", "segmentation-offloads", "operstates", "kapi",
            "timestamping", "af_xdp", "packet_mmap", "filter", "msg_zerocopy", "devmem",
            "xdp-rx-metadata", "xsk-tx-metadata", "net_dim", "netif-msg", "strparser",
            "generic_netlink", "sysfs-tagging", "failover", "net_failover", "multi-pf-netdev",
            "representors", "sriov",
        ],
    ),
    (
        "Routing (L3)",
        [
            "fib_trie", "nexthop-group-resilient", "vrf", "ipv6", "ila", "ip-sysctl",
            "seg6-sysctl", "mpls-sysctl", "ioam6-sysctl", "ip_dynaddr", "alias",
        ],
    ),
    (
        "Transport (L4)",
        [
            "tcp_ao", "tcp-thin", "dctcp", "mptcp", "mptcp-sysctl", "udplite", "sctp", "dccp",
            "kcm", "tls*", "proc_net_tcp", "smc-sysctl", "rds", "dns_resolver",
        ],
    ),
    (
        "Netfilter and IPsec",
        [
            "nf_flowtable", "nf_conntrack-sysctl", "netfilter-sysctl", "ipvs-sysctl", "tproxy",
            "ipsec", "xfrm_*", "secid",
        ],
    ),
    (
        "L2 switching and virtual devices",
        [
            "bridge", "switchdev", "dsa/*", "bonding", "team", "vxlan", "ipvlan", "gtp", "l2tp",
            "tuntap", "openvswitch", "tc-*", "devlink/*", "bareudp", "caif/*",
        ],
    ),
    (
        "PHY and link hardware frameworks",
        ["phy", "sfp-phylink", "phy-link-topology", "oa-tc6-framework", "pse-pd/*"],
    ),
    (
        "Observability",
        [
            "snmp_counter", "statistics", "gen_stats", "xfrm_proc", "net_cachelines/*", "pktgen",
            "netconsole", "ethtool-netlink",
        ],
    ),
]

NETLINK_CLUSTERS = [
    ("Routing and addressing (rtnetlink)", ["specs/rt_route", "specs/rt_addr", "specs/rt_link"]),
    ("Device and datapath config", ["specs/netdev", "specs/ethtool", "specs/devlink", "specs/dpll"]),
    ("Traffic control and filtering", ["specs/tc", "specs/nftables"]),
    ("Transport", ["specs/mptcp_pm", "specs/tcp_metrics", "specs/handshake", "specs/fou"]),
    (
        "Virtual switching and devices",
        ["specs/ovs_datapath", "specs/ovs_flow", "specs/ovs_vport", "specs/team"],
    ),
    ("Netlink meta", ["specs/nlctrl"]),
    ("Netlink spec schemas", ["genetlink*", "netlink-raw"]),
]

BPF_CLUSTERS = [
    (
        "BPF networking datapath",
        [
            "map_devmap", "map_cpumap", "map_xskmap", "map_sockmap", "map_sk_storage",
            "map_lpm_trie", "redirect", "prog_flow_dissector", "prog_sk_lookup",
            "prog_cgroup_sockopt", "classic_vs_extended",
        ],
    ),
    ("Core BPF mechanics", ["*"]),
]

FOLDER_CLUSTERS = {
    "networking": NETWORKING_CLUSTERS,
    "netlink": NETLINK_CLUSTERS,
    "bpf": BPF_CLUSTERS,
    "netlabel": [("Labeled networking (NetLabel)", ["*"])],
    "infiniband": [("RDMA and InfiniBand", ["*"])],
}


def doc_cluster(doc_path: str) -> str:
    folder, _, rest = doc_path.partition("/")
    stem = rest.rsplit(".", 1)[0]
    for cluster, patterns in FOLDER_CLUSTERS.get(folder, []):
        if _matches(stem, patterns):
            return cluster
    return "Other networking"


# --------------------------------------------------------------------------------------
# Code
# --------------------------------------------------------------------------------------

AREAS = [
    "include/uapi/linux",
    "include/trace/events",
    "include/linux",
    "include/net",
    "drivers/net",
    "kernel/bpf",
    "net",
    "lib",
]

NET_SUBFOLDERS = [
    "8021q", "bpf", "bridge", "core", "dcb", "dccp", "devlink", "dns_resolver", "dsa",
    "ethernet", "ethtool", "handshake", "ife", "ipv4", "ipv6", "kcm", "key", "l2tp", "l3mdev",
    "mpls", "mptcp", "netfilter", "netlabel", "netlink", "nsh", "openvswitch", "packet",
    "psample", "rds", "sched", "sctp", "smc", "strparser", "switchdev", "tls", "unix", "xdp",
    "xfrm",
]

INCLUDE_NET_EXCLUDE = ["9p", "bluetooth", "caif", "iucv", "nfc", "phonet", "mana", "libeth"]

INCLUDE_LINUX_FILES = [
    "bpf-cgroup-defs.h", "bpf-cgroup.h", "bpf-netns.h", "bpf.h", "bpf_local_storage.h",
    "bpf_mem_alloc.h", "bpf_mprog.h", "bpf_types.h", "bpf_verifier.h", "bpfptr.h", "btf.h",
    "btf_ids.h", "cookie.h", "dccp.h", "dim.h", "dns_resolver.h", "dynamic_queue_limits.h",
    "errqueue.h", "etherdevice.h", "ethtool.h", "ethtool_netlink.h", "filter.h",
    "fwnode_mdio.h", "icmp.h", "icmpv6.h", "if_arp.h", "if_bridge.h", "if_ether.h",
    "if_link.h", "if_macvlan.h", "if_pppol2tp.h", "if_pppox.h", "if_tap.h", "if_team.h",
    "if_tun.h", "if_tunnel.h", "if_vlan.h", "igmp.h", "in.h", "in6.h",
    "indirect_call_wrapper.h", "inet.h", "inet_diag.h", "inetdevice.h", "ioam6_genl.h",
    "ioam6_iptunnel.h", "ip.h", "ipv6.h", "ipv6_route.h", "l2tp.h", "mdio.h", "mii.h",
    "mii_timestamper.h", "mpls.h", "mpls_iptunnel.h", "mroute.h", "mroute6.h",
    "mroute_base.h", "net.h", "net_tstamp.h", "netdev_features.h", "netdevice.h",
    "netdevice_xmit.h", "netfilter.h", "netfilter_bridge.h", "netfilter_defs.h",
    "netfilter_ipv4.h", "netfilter_ipv6.h", "netfilter_netdev.h", "netlink.h", "netpoll.h",
    "of_mdio.h", "of_net.h", "openvswitch.h", "phy.h", "phy_fixed.h", "phy_link_topology.h",
    "phylink.h", "pim.h", "ptp_classify.h", "ptr_ring.h", "rtnetlink.h", "sctp.h", "seg6.h",
    "seg6_genl.h", "seg6_hmac.h", "seg6_iptunnel.h", "seg6_local.h", "seq_file_net.h",
    "sfp.h", "skb_array.h", "skbuff.h", "skbuff_ref.h", "skmsg.h", "sock_diag.h",
    "socket.h", "sockptr.h", "tcp.h", "u64_stats_sync.h", "udp.h", "virtio_net.h",
    "win_minmax.h",
]
INCLUDE_LINUX_SUBFOLDERS = [
    "dsa", "mdio", "net", "netfilter", "netfilter_arp", "netfilter_bridge", "netfilter_ipv4",
    "netfilter_ipv6", "pcs", "phy", "pse-pd",
]

INCLUDE_UAPI_FILES = [
    "amt.h", "bpf.h", "bpf_common.h", "btf.h", "cfm_bridge.h", "dcbnl.h", "dccp.h",
    "devlink.h", "dns_resolver.h", "dpll.h", "errqueue.h", "erspan.h", "ethtool.h",
    "ethtool_netlink.h", "fib_rules.h", "filter.h", "fou.h", "gen_stats.h", "genetlink.h",
    "gtp.h", "handshake.h", "icmp.h", "icmpv6.h", "if.h", "if_addr.h", "if_addrlabel.h",
    "if_arp.h", "if_bonding.h", "if_bridge.h", "if_ether.h", "if_infiniband.h", "if_link.h",
    "if_macsec.h", "if_packet.h", "if_pppol2tp.h", "if_pppox.h", "if_team.h", "if_tun.h",
    "if_tunnel.h", "if_vlan.h", "if_xdp.h", "ife.h", "igmp.h", "ila.h", "in.h", "in6.h",
    "in_route.h", "inet_diag.h", "ioam6.h", "ioam6_genl.h", "ioam6_iptunnel.h", "ip.h",
    "ip6_tunnel.h", "ip_vs.h", "ipsec.h", "ipv6.h", "ipv6_route.h", "kcm.h", "l2tp.h",
    "lwtunnel.h", "mdio.h", "mii.h", "mpls.h", "mpls_iptunnel.h", "mptcp.h", "mptcp_pm.h",
    "mroute.h", "mroute6.h", "mrp_bridge.h", "neighbour.h", "net.h", "net_dropmon.h",
    "net_namespace.h", "net_tstamp.h", "netconf.h", "netdev.h", "netdevice.h",
    "netfilter.h", "netfilter_arp.h", "netfilter_bridge.h", "netfilter_ipv4.h",
    "netfilter_ipv6.h", "netlink.h", "netlink_diag.h", "nexthop.h", "openvswitch.h",
    "packet_diag.h", "pfkeyv2.h", "pkt_cls.h", "pkt_sched.h", "psample.h", "rds.h",
    "route.h", "rpl.h", "rpl_iptunnel.h", "rtnetlink.h", "sctp.h", "seg6.h", "seg6_genl.h",
    "seg6_hmac.h", "seg6_iptunnel.h", "seg6_local.h", "smc.h", "smc_diag.h", "snmp.h",
    "sock_diag.h", "socket.h", "sockios.h", "tcp.h", "tcp_metrics.h", "tls.h", "udp.h",
    "un.h", "unix_diag.h", "veth.h", "virtio_net.h", "wireguard.h", "xdp_diag.h", "xfrm.h",
]
INCLUDE_UAPI_SUBFOLDERS = [
    "netfilter", "netfilter_arp", "netfilter_bridge", "netfilter_ipv4", "netfilter_ipv6",
    "tc_act", "tc_ematch",
]

TRACE_EVENT_HEADERS = [
    "net", "skb", "sock", "tcp", "udp", "napi", "neigh", "fib", "fib6", "qdisc", "xdp",
    "page_pool", "bridge", "devlink", "mptcp", "icmp", "netlink", "handshake", "sctp",
    "bpf_test_run", "net_probe_common",
]

DRIVERS_NET_SUBFOLDERS = [
    "bonding", "team", "vxlan", "ipvlan", "phy", "mdio", "pcs", "netdevsim", "wireguard",
]

LIB_PATHS = ["lib/dim/", "lib/net_utils.c"]

SOURCE_SUFFIXES = (".c", ".h")
BUILD_FILE_NAMES = ("Kconfig", "Makefile")

# Files outside the code scope that the index build reads for metadata or registries.
EXTRA_BUILD_INPUTS = ["MAINTAINERS"]


def _is_indexable_name(name: str) -> bool:
    return name.endswith(SOURCE_SUFFIXES) or name in BUILD_FILE_NAMES or name.startswith("Kconfig.")


def code_area(path: str) -> str | None:
    for area in AREAS:
        if path.startswith(area + "/"):
            return area
    return None


def code_in_scope(path: str) -> bool:
    """path is a repo path, e.g. "net/ipv4/fib_trie.c"."""
    name = path.rsplit("/", 1)[-1]
    if not _is_indexable_name(name):
        return False
    area = code_area(path)
    if area is None:
        return False
    parts = path[len(area) + 1 :].split("/")
    first = parts[0]
    nested = len(parts) > 1
    if area == "net":
        return not nested or first in NET_SUBFOLDERS
    if area == "include/net":
        return not (nested and first in INCLUDE_NET_EXCLUDE)
    if area == "include/linux":
        return first in INCLUDE_LINUX_SUBFOLDERS if nested else first in INCLUDE_LINUX_FILES
    if area == "include/uapi/linux":
        return first in INCLUDE_UAPI_SUBFOLDERS if nested else first in INCLUDE_UAPI_FILES
    if area == "include/trace/events":
        return not nested and first[:-2] in TRACE_EVENT_HEADERS
    if area == "drivers/net":
        return first in DRIVERS_NET_SUBFOLDERS if nested else True
    if area == "kernel/bpf":
        return True
    if area == "lib":
        return any(path == p or (p.endswith("/") and path.startswith(p)) for p in LIB_PATHS)
    return False


def file_type(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    if name == "Makefile":
        return "makefile"
    if name.startswith("Kconfig"):
        return "kconfig"
    if path.startswith("include/uapi/"):
        return "uapi_h"
    if path.startswith("include/trace/events/"):
        return "trace_h"
    return "h" if name.endswith(".h") else "c"


def subsystem(path: str) -> str | None:
    """First folder below the area, or None for files directly in the area."""
    area = code_area(path)
    if area is None:
        return None
    parts = path[len(area) + 1 :].split("/")
    return parts[0] if len(parts) > 1 else None


def out_of_scope_reason(path: str) -> str:
    return (
        f"{path} is outside the v1 networking scope of this server "
        "(net/, include/net/, networking parts of include/linux/ and include/uapi/linux/, "
        "networking tracepoints, the drivers/net/ framework, kernel/bpf/, lib/dim/)"
    )
