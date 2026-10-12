"""Curated alias list for networking concepts.

Each canonical tag maps to the spellings that should collapse into it, so that the wording of
a question ("connection tracking", "receive offload") finds files whose paths and symbols use
another spelling (`nf_conntrack`, `gro`). This is the only hand-maintained input to tagging.
"""

CONCEPTS: dict[str, list[str]] = {
    # datapath and buffers
    "skb": ["sk_buff", "skbuff", "socket buffer", "sk buff"],
    "napi": ["new api", "napi poll", "napi_struct", "busy poll", "busy polling"],
    "gro": ["generic receive offload", "receive offload", "gro_receive", "napi_gro"],
    "gso": ["generic segmentation offload", "segmentation offload", "skb_segment"],
    "tso": ["tcp segmentation offload"],
    "lro": ["large receive offload"],
    "checksum": ["csum", "checksum offload", "checksumming"],
    "xdp": ["express data path", "xdp_buff", "xdp_frame"],
    "af_xdp": ["xsk", "xdp socket", "xdp sockets", "xskmap"],
    "page_pool": ["page pool", "pp_alloc"],
    "rps": ["receive packet steering"],
    "rfs": ["receive flow steering", "arfs", "accelerated rfs"],
    "xps": ["transmit packet steering"],
    "rss": ["receive side scaling", "rx hash", "rxhash"],
    "netdevice": ["net_device", "netdev", "network device", "network interface"],
    "qdisc": ["queueing discipline", "queuing discipline", "traffic control", "packet scheduler", "sch"],
    "tc": ["tc filter", "classifier", "cls", "tcf"],
    "tc_action": ["act", "tc action", "tc actions"],
    "bql": ["byte queue limits", "dynamic queue limits", "dql"],
    "zerocopy": ["zero copy", "msg_zerocopy", "zero-copy"],
    "timestamping": ["so_timestamping", "hwtstamp", "hardware timestamp", "tx timestamp"],
    "ptp": ["precision time protocol", "phc"],
    "flow_dissector": ["flow dissector", "flow dissection", "flow keys", "flow_keys"],
    "loopback": ["lo device"],
    # routing
    "fib": ["forwarding information base", "fib_table", "route lookup", "routing table", "fib trie", "fib_trie", "lc-trie", "lpc-trie"],
    "routing": ["route", "routes", "rtable", "rt6_info", "dst_entry", "dst cache", "routing cache"],
    "ecmp": ["equal cost multipath", "equal-cost multipath", "multipath hash", "multipath route", "multipath routing", "fib multipath", "route multipath", "nexthop selection"],
    "nexthop": ["next hop", "next-hop", "nexthop group", "nh_grp", "fib_nh"],
    "policy_routing": ["fib rules", "fib_rules", "policy routing", "ip rule", "routing policy"],
    "neighbour": ["neighbor", "neigh", "arp table", "neighbour table", "neighbor discovery"],
    "arp": ["address resolution protocol"],
    "ndisc": ["neighbour discovery", "nd_tbl", "router advertisement", "router solicitation"],
    "vrf": ["virtual routing and forwarding", "l3mdev", "l3 master device"],
    "mpls": ["label switching", "multiprotocol label switching"],
    "segment_routing": ["seg6", "srv6", "segment routing", "srh"],
    "ioam": ["ioam6", "in-situ oam"],
    "lwtunnel": ["lightweight tunnel", "lwt", "light weight tunnel"],
    "multicast_routing": ["ipmr", "ip6mr", "mroute", "multicast routing", "pim"],
    "igmp": ["mld", "multicast listener", "group membership"],
    "pmtu": ["path mtu", "path mtu discovery", "mtu discovery", "pmtud"],
    "fragmentation": ["ip fragment", "defrag", "reassembly", "ip_frag", "inet_frag"],
    "icmp": ["icmpv6", "ping", "echo request"],
    "forwarding": ["ip_forward", "ip forwarding", "packet forwarding"],
    "addrconf": ["address configuration", "slaac", "autoconf", "ipv6 address"],
    "inetdev": ["in_device", "inet device", "ipv4 address", "ifa", "in_ifaddr"],
    # transport
    "tcp": ["transmission control protocol", "tcp_sock"],
    "congestion_control": ["congestion control", "cong", "cwnd", "congestion window", "tcp_congestion_ops", "cubic", "bbr", "reno", "dctcp"],
    "retransmission": ["retransmit", "rto", "loss recovery", "rack", "tail loss probe", "tlp", "loss probe", "fast retransmit"],
    "sack": ["selective acknowledgment", "selective ack", "dsack"],
    "fastopen": ["tcp fast open", "tfo", "fast open"],
    "syncookies": ["syn cookies", "syn cookie", "syn flood"],
    "tcp_ao": ["authentication option", "tcp-ao"],
    "tcp_md5": ["md5sig", "tcp md5", "md5 signature"],
    "udp": ["user datagram protocol", "udplite", "udp-lite"],
    "udp_tunnel": ["udp tunnel", "udp encapsulation", "fou", "gue", "foo over udp"],
    "mptcp": ["multipath tcp", "subflow", "path manager"],
    "sctp": ["stream control transmission protocol", "association"],
    "dccp": ["datagram congestion control protocol"],
    "tls": ["ktls", "kernel tls", "transport layer security", "tls offload"],
    "smc": ["shared memory communications", "smc-r", "smc-d"],
    "rds": ["reliable datagram sockets"],
    "kcm": ["kernel connection multiplexor"],
    "socket": ["sock", "struct sock", "sockets", "bsd socket", "sk_alloc"],
    "socket_options": ["sockopt", "setsockopt", "getsockopt", "so_"],
    "listen": ["accept queue", "request sock", "reqsk", "syn queue", "inet_csk_accept"],
    "hashtables": ["inet_hashtables", "ehash", "bind hash", "bhash", "socket lookup", "established hash"],
    "timewait": ["time_wait", "tw_sock", "inet_timewait"],
    "unix_socket": ["af_unix", "unix domain socket", "unix sockets", "scm_rights"],
    "packet_socket": ["af_packet", "packet_mmap", "tpacket", "raw socket capture"],
    "raw_socket": ["raw sockets", "sock_raw", "af_inet raw"],
    "strparser": ["stream parser"],
    # netfilter and security
    "netfilter": ["nf_hook", "nf hooks", "netfilter hook", "nf_hook_ops"],
    "conntrack": ["nf_conntrack", "connection tracking", "nf_conn", "ct state"],
    "nat": ["nf_nat", "network address translation", "masquerade", "snat", "dnat"],
    "nftables": ["nf_tables", "nft", "nft_expr"],
    "iptables": ["xtables", "x_tables", "xt_match", "xt_target", "ip_tables", "ip6_tables"],
    "ipset": ["ip_set", "ip sets"],
    "ipvs": ["ip_vs", "ip virtual server", "virtual server", "load balancer"],
    "flowtable": ["nf_flowtable", "flow offload", "nf_flow_table", "flow table"],
    "tproxy": ["transparent proxy"],
    "nfnetlink": ["nfnl", "netfilter netlink"],
    "xfrm": ["ipsec", "transform", "security association", "xfrm_state", "xfrm_policy", "esp", "ah"],
    "netlabel": ["cipso", "calipso", "labeled networking", "netlbl"],
    # layer 2 and virtual devices
    "bridge": ["br_", "bridging", "802.1d", "fdb", "forwarding database", "stp", "spanning tree"],
    "vlan": ["8021q", "802.1q", "vlan tag", "vlan_dev"],
    "bonding": ["bond", "link aggregation", "lacp", "802.3ad", "slave"],
    "team": ["team driver", "teaming"],
    "vxlan": ["virtual extensible lan", "vni", "vtep"],
    "geneve": ["generic network virtualization encapsulation"],
    "gre": ["generic routing encapsulation", "ip_gre", "erspan"],
    "tunnel": ["ip_tunnel", "ip6_tunnel", "ipip", "sit", "encapsulation", "decapsulation"],
    "macvlan": ["macvtap", "ipvlan", "ipvtap"],
    "veth": ["virtual ethernet pair", "veth pair"],
    "tuntap": ["tun", "tap", "tun/tap"],
    "wireguard": ["wg", "noise protocol"],
    "openvswitch": ["ovs", "open vswitch", "datapath flow"],
    "switchdev": ["switch device", "hardware offload", "hw offload"],
    "dsa": ["distributed switch architecture", "tag driver", "switch tagging"],
    "devlink": ["devlink port", "devlink health", "devlink trap"],
    "ethtool": ["ethnl", "ethtool netlink", "link modes", "link settings"],
    "phy": ["phylib", "phy device", "phy driver", "phylink", "mii", "mdio", "sfp"],
    "ethernet": ["eth_type_trans", "ether", "mac address", "802.3"],
    # control plane and infrastructure
    "netlink": ["nlmsg", "nlattr", "netlink socket", "netlink message", "nla_"],
    "rtnetlink": ["rtnl", "rtm_", "rtnl_lock", "routing netlink"],
    "genetlink": ["generic netlink", "genl", "genl_family"],
    "netns": ["network namespace", "net namespace", "pernet", "struct net", "nsid"],
    "sysctl": ["ctl_table", "proc sys", "tunable"],
    "procfs": ["proc_net", "seq_file", "/proc/net"],
    "snmp": ["mib", "counters", "statistics", "netstat", "nstat"],
    "tracepoint": ["trace event", "trace events", "tracing"],
    "drop_reason": ["skb drop reason", "kfree_skb_reason", "drop monitor", "dropwatch"],
    "notifier": ["netdev notifier", "notifier chain", "netdevice notifier"],
    # bpf
    "bpf": ["ebpf", "berkeley packet filter", "bpf program", "bpf_prog"],
    "bpf_verifier": ["verifier", "verification", "bpf_verifier_env"],
    "bpf_helper": ["bpf helper", "bpf helpers", "bpf_func_proto", "helper function"],
    "bpf_map": ["bpf maps", "map type", "bpf_map_ops"],
    "btf": ["bpf type format"],
    "kfunc": ["kfuncs", "kernel function call"],
    "devmap": ["dev_map", "device map", "xdp redirect map"],
    "cpumap": ["cpu_map", "cpu map", "cpu redirect"],
    "sockmap": ["sock_map", "sockhash", "sk_msg", "sk_skb", "socket redirect"],
    "lpm_trie": ["longest prefix match", "lpm trie", "prefix match"],
    "socket_filter": ["sk_filter", "classic bpf", "cbpf", "so_attach_filter"],
    "cgroup_bpf": ["cgroup bpf", "cgroup skb", "cgroup sock"],
    "redirect": ["xdp_redirect", "bpf_redirect", "redirect map"],
    "dim": ["dynamic interrupt moderation", "net_dim", "interrupt moderation"],
}


def alias_rows() -> list[tuple[str, str]]:
    rows = []
    for canonical, aliases in CONCEPTS.items():
        rows.append((canonical, canonical))
        for alias in aliases:
            rows.append((alias.lower(), canonical))
    seen = set()
    unique = []
    for alias, canonical in rows:
        if alias not in seen:
            seen.add(alias)
            unique.append((alias, canonical))
    return unique
