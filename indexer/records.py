"""Structured datasets extracted from documentation (the `doc_records` table).

Each parser reads one doc family whose layout is regular enough to split into records:
sysctls, SNMP and XFRM counters, struct fast-path layouts, ethtool messages, operational
states, the /proc/net/tcp line format, and the BPF program-type, map-type, kfunc, BTF and
instruction-set tables.
"""

import re
from dataclasses import dataclass, field

from indexer.docs import Doc, Section, slugify


@dataclass
class Record:
    dataset: str
    key: str
    doc_id: str
    line: int
    end_line: int
    attrs: dict = field(default_factory=dict)
    aliases: list[str] = field(default_factory=list)
    text: str = ""  # searchable text; not stored

    @property
    def record_id(self) -> str:
        return f"{self.dataset}/{self.key}"


def _section_at(doc: Doc, line: int) -> Section:
    """The innermost section containing a 1-based line."""
    best = doc.sections[0]
    for section in doc.sections:
        if section.start_line <= line <= section.end_line and section.level >= best.level:
            best = section
    return best


def _paragraph(lines: list[str], start: int, limit: int = 3) -> str:
    """First paragraph at or after index `start`, as one line."""
    collected = []
    for line in lines[start:]:
        if not line.strip():
            if collected:
                break
            continue
        collected.append(line.strip())
        if len(collected) >= limit:
            break
    return " ".join(collected)


def _first_prose(lines: list[str], section: Section) -> str:
    """First ordinary paragraph of a section, skipping its heading and any directives."""

    def adornment(line: str) -> bool:
        stripped = line.strip()
        return len(stripped) >= 3 and stripped == stripped[0] * len(stripped) and not stripped[0].isalnum()

    index = section.start_line - 1
    end = min(section.body_end_line, len(lines))
    while index < end:
        line = lines[index]
        following = lines[index + 1] if index + 1 < end else ""
        if line.startswith(".. "):
            index += 1
            while index < end and (not lines[index].strip() or lines[index][:1] in (" ", "\t")):
                index += 1
            continue
        if not line.strip() or adornment(line) or adornment(following) or line[:1].isspace():
            index += 1
            continue
        return _paragraph(lines, index, limit=6)
    return ""


# --------------------------------------------------------------------------------------
# Sysctls
# --------------------------------------------------------------------------------------

SYSCTL_DOCS = {
    "networking/ip-sysctl.rst": "net.ipv4",
    "networking/nf_conntrack-sysctl.rst": "net.netfilter",
    "networking/netfilter-sysctl.rst": "net.netfilter",
    "networking/ipvs-sysctl.rst": "net.ipv4.vs",
    "networking/mpls-sysctl.rst": "net.mpls",
    "networking/mptcp-sysctl.rst": "net.mptcp",
    "networking/seg6-sysctl.rst": "net.ipv6",
    "networking/ioam6-sysctl.rst": "net.ipv6",
    "networking/smc-sysctl.rst": "net.smc",
    "networking/xfrm_sysctl.rst": "net.core",
}
_SYSCTL_ENTRY_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_/.\[\]<>*-]*)\s+-\s+(\S.*)$")
_SYSCTL_PATH_RE = re.compile(r"/?proc/sys/(net/[A-Za-z0-9_/<>]+?)/?(?:\*|[a-z0-9_]+_\*)")
_SYSCTL_SUBDIR_RE = re.compile(r"^``((?:conf|neigh|route|icmp)/[A-Za-z0-9_*/]*)``:?\s*$")


def _sysctl_prefix_from_heading(text: str) -> str | None:
    match = _SYSCTL_PATH_RE.search(text.replace("``", ""))
    if not match:
        return None
    return re.sub(r"<[a-z]+>", "<dev>", match.group(1)).replace("/", ".")


def parse_sysctls(doc: Doc, lines: list[str]) -> list[Record]:
    base = SYSCTL_DOCS[doc.doc_path]
    records: list[Record] = []
    prefix = base
    subdir = ""
    heading_lines = {s.start_line: s for s in doc.sections}
    total = len(lines)
    entry_starts = []
    for index in range(total):
        line = lines[index]
        section = heading_lines.get(index + 1)
        if section is not None and section.level > 0:
            found = _sysctl_prefix_from_heading(section.heading)
            if found:
                prefix, subdir = found, ""
            elif section.level == 1:
                subdir = ""
        marker = _SYSCTL_SUBDIR_RE.match(line)
        if marker:
            folder = marker.group(1).rstrip("*/").replace("interface", "<dev>").replace("/", ".")
            subdir = folder
            continue
        found_inline = _sysctl_prefix_from_heading(line) if line.startswith(("``/proc", "``proc")) else None
        if found_inline:
            prefix, subdir = found_inline, ""
            continue
        match = _SYSCTL_ENTRY_RE.match(line)
        following = lines[index + 1] if index + 1 < total else ""
        if match and (following[:1] in ("\t", " ") or not following.strip()):
            entry_starts.append((index, match.group(1), match.group(2).strip(), prefix, subdir))
    for position, (index, name, value_type, entry_prefix, entry_subdir) in enumerate(entry_starts):
        end = entry_starts[position + 1][0] if position + 1 < len(entry_starts) else total
        section = _section_at(doc, index + 1)
        end = min(end, section.end_line)
        # stop at a column-0 line that is not part of the entry (a marker or a heading)
        for probe in range(index + 1, end):
            if lines[probe] and not lines[probe][0].isspace():
                end = probe
                break
        while end > index + 1 and not lines[end - 1].strip():
            end -= 1
        body = [l.strip() for l in lines[index + 1 : end]]
        description = " ".join(l for l in body if l)
        default = None
        default_match = re.search(r"\bDefault(?:\s+value)?\s*(?:is|:|=)\s*([^\n.;]{1,60})", "\n".join(body), re.IGNORECASE)
        if default_match:
            default = default_match.group(1).strip()
        relative = re.sub(r"<[a-z]+>|\binterface\b", "<dev>", name).replace("/", ".")
        parts = [entry_prefix]
        if entry_subdir and not relative.startswith(("conf.", "neigh.", "route.", "icmp.")):
            parts.append(entry_subdir)
        parts.append(relative)
        key = ".".join(parts)
        procname = relative.rsplit(".", 1)[-1]
        records.append(
            Record(
                dataset="sysctl", key=key, doc_id=section.doc_id, line=index + 1, end_line=end,
                attrs={
                    "name": name, "procname": procname, "value_type": value_type,
                    "default": default, "description": description[:1500],
                    "documented_in": doc.doc_path,
                },
                aliases=[procname, name],
                text=f"{name} {value_type} {description[:600]}",
            )
        )
    return records


# --------------------------------------------------------------------------------------
# SNMP and XFRM counters
# --------------------------------------------------------------------------------------

_SNMP_BULLET_RE = re.compile(r"^\* ((?:[A-Z][A-Za-z0-9]+)(?:(?:, | and |, and )[A-Z][A-Za-z0-9]+)*)\s*$")


def parse_snmp(doc: Doc, lines: list[str]) -> list[Record]:
    records = []
    starts = [(i, m.group(1)) for i, line in enumerate(lines) if (m := _SNMP_BULLET_RE.match(line))]
    for position, (index, names_text) in enumerate(starts):
        section = _section_at(doc, index + 1)
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        end = min(end, section.end_line)
        body = [l.strip() for l in lines[index + 1 : end] if l.strip() and not l.startswith(".. _")]
        description = " ".join(body)
        rfc = re.search(r"Defined in `(RFC\d+)[^`]*`_", description)
        names = re.split(r", and |, | and ", names_text)
        functions = sorted(set(re.findall(r"\b([a-z][a-z0-9]*_[a-z0-9_]+)\b(?= function|\(\))", description)))
        for name in names:
            records.append(
                Record(
                    dataset="snmp", key=name, doc_id=section.doc_id, line=index + 1, end_line=end,
                    attrs={
                        "description": description[:1500], "rfc": rfc.group(1) if rfc else None,
                        "documented_with": [n for n in names if n != name],
                        "functions_mentioned": functions,
                    },
                    text=f"{name} {description[:600]}",
                )
            )
    return records


def parse_xfrm_counters(doc: Doc, lines: list[str]) -> list[Record]:
    records = []
    for index, line in enumerate(lines):
        match = re.match(r"^(Xfrm[A-Za-z0-9]+):\s*$", line)
        if not match:
            continue
        end = index + 1
        while end < len(lines) and (lines[end][:1] in ("\t", " ") and lines[end].strip()):
            end += 1
        section = _section_at(doc, index + 1)
        description = " ".join(l.strip() for l in lines[index + 1 : end])
        direction = "inbound" if "Inbound" in section.heading else "outbound" if "Outbound" in section.heading else None
        records.append(
            Record(
                dataset="xfrm_counter", key=match.group(1), doc_id=section.doc_id, line=index + 1,
                end_line=end, attrs={"description": description, "direction": direction,
                                     "proc_file": "/proc/net/xfrm_stat"},
                text=f"{match.group(1)} {description}",
            )
        )
    return records


# --------------------------------------------------------------------------------------
# net_cachelines: struct fast-path layouts
# --------------------------------------------------------------------------------------

_NOT_FUNCTIONS = {"tx", "rx", "write", "read", "read_mostly", "read_write", "write_mostly"}


def parse_net_cachelines(doc: Doc, lines: list[str]) -> list[Record]:
    stem = doc.doc_path.rsplit("/", 1)[-1][: -len(".rst")]
    if stem == "index":
        return []
    container = stem
    header_index = next(
        (i for i, l in enumerate(lines) if re.match(r"^Type\s{2,}Name\s{2,}fastpath_tx", l)), None
    )
    if header_index is None:
        return []
    records = []
    seen: dict[str, int] = {}
    for index in range(header_index + 1, len(lines)):
        line = lines[index].rstrip()
        if not line.strip():
            continue
        columns = re.split(r"\s{2,}", line.strip())
        if columns[0].startswith(".."):
            named = [c for c in columns if c.startswith("..") and c not in ("..struct", "..enum")]
            if named:
                container = named[0].lstrip(".")
            continue
        if len(columns) < 2:
            continue
        field_type, name = columns[0], columns[1]
        tx = columns[2] if len(columns) > 2 else ""
        rx = columns[3] if len(columns) > 3 else ""
        comment = " ".join(columns[4:]) if len(columns) > 4 else ""
        functions = sorted(
            {
                token
                for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", comment.replace("-", "_"))
                if token not in _NOT_FUNCTIONS and "_" in token
            }
        )
        field_name = re.sub(r"\[.*\]$", "", name)
        key = f"{container}.{field_name}"
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            key = f"{key}@{index + 1}"
        records.append(
            Record(
                dataset="net_cachelines", key=key, doc_id=doc.sections[0].doc_id, line=index + 1,
                end_line=index + 1,
                attrs={
                    "struct": container, "field": name, "type": field_type.replace("_", " ", 1) if field_type.startswith("struct_") else field_type,
                    "fastpath_tx_access": tx or None, "fastpath_rx_access": rx or None,
                    "comment": comment or None, "functions": functions,
                },
                aliases=[field_name],
                text=f"{container} {name} {field_type} {tx} {rx} {comment}",
            )
        )
    return records


# --------------------------------------------------------------------------------------
# ethtool netlink messages, operational states, /proc/net/tcp
# --------------------------------------------------------------------------------------


def parse_ethtool_messages(doc: Doc, lines: list[str]) -> list[Record]:
    records = []
    direction = None
    by_heading = {s.heading: s for s in doc.sections}
    for index, line in enumerate(lines):
        if line.startswith("Userspace to kernel:"):
            direction = "userspace_to_kernel"
        elif line.startswith("Kernel to userspace:"):
            direction = "kernel_to_userspace"
        match = re.match(r"^\s+``(ETHTOOL_MSG_[A-Z0-9_]+)``\s+(\S.*)$", line)
        if not match or direction is None:
            continue
        name, summary = match.group(1), match.group(2).strip()
        short = name[len("ETHTOOL_MSG_"):]
        section = by_heading.get(short)
        if section is None and short.endswith(("_REPLY", "_NTF")):
            section = by_heading.get(re.sub(r"_(GET_REPLY|SET_REPLY|ACT_REPLY|REPLY|NTF)$", "_GET", short))
        attributes = []
        if section is not None:
            block = lines[section.start_line - 1 : section.end_line]
            attributes = sorted(set(re.findall(r"``(ETHTOOL_A_[A-Z0-9_]+)``", "\n".join(block))))
        records.append(
            Record(
                dataset="ethtool_msg", key=name, doc_id=(section or _section_at(doc, index + 1)).doc_id,
                line=index + 1, end_line=index + 1,
                attrs={"summary": summary, "direction": direction, "attributes": attributes,
                       "netlink_spec": "netlink/specs/ethtool.yaml"},
                aliases=[short],
                text=f"{name} {summary} {' '.join(attributes)}",
            )
        )
    return records


def parse_operstates(doc: Doc, lines: list[str]) -> list[Record]:
    records = []
    for index, line in enumerate(lines):
        match = re.match(r"^(IF_OPER_[A-Z]+) \((\d+)\):\s*$", line)
        if not match:
            continue
        end = index + 1
        while end < len(lines) and lines[end].strip() and lines[end][:1] in (" ", "\t"):
            end += 1
        description = " ".join(l.strip() for l in lines[index + 1 : end])
        records.append(
            Record(
                dataset="operstate", key=match.group(1), doc_id=_section_at(doc, index + 1).doc_id,
                line=index + 1, end_line=end,
                attrs={"value": int(match.group(2)), "description": description,
                       "defined_in": "include/uapi/linux/if.h"},
                aliases=[match.group(2)],
                text=f"{match.group(1)} {description}",
            )
        )
    return records


def parse_proc_net_tcp(doc: Doc, lines: list[str]) -> list[Record]:
    records = []
    for index, line in enumerate(lines):
        match = re.match(r"^[\s|]*\|-+>\s*(\S.*)$", line)
        if not match:
            continue
        description = match.group(1).strip()
        probe = index + 1
        while probe < len(lines) and re.match(r"^[\s|]+[^\s|-]", lines[probe]) and "-->" not in lines[probe]:
            description += " " + re.sub(r"^[\s|]+", "", lines[probe]).strip()
            probe += 1
        records.append(
            Record(
                dataset="proc_net_tcp", key=slugify(description.split(",")[0])[:60],
                doc_id=_section_at(doc, index + 1).doc_id, line=index + 1, end_line=probe,
                attrs={"description": description, "diagram_line": index + 1,
                       "implemented_by": ["tcp4_seq_show", "tcp6_seq_show"]},
                text=description,
            )
        )
    # the diagram lists fields right-to-left within each of its three parts
    part: list[Record] = []
    ordered: list[Record] = []
    previous_line = None
    for record in records:
        if previous_line is not None and record.line - previous_line > 3:
            ordered += reversed(part)
            part = []
        part.append(record)
        previous_line = record.end_line
    ordered += reversed(part)
    for position, record in enumerate(ordered, start=1):
        record.attrs["position"] = position
    return ordered


# --------------------------------------------------------------------------------------
# BPF
# --------------------------------------------------------------------------------------

NETWORKING_PROG_TYPES = {
    "BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_SCHED_CLS", "BPF_PROG_TYPE_SCHED_ACT",
    "BPF_PROG_TYPE_SK_SKB", "BPF_PROG_TYPE_SK_MSG", "BPF_PROG_TYPE_SOCK_OPS",
    "BPF_PROG_TYPE_CGROUP_SKB", "BPF_PROG_TYPE_CGROUP_SOCK", "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
    "BPF_PROG_TYPE_CGROUP_SOCKOPT", "BPF_PROG_TYPE_SOCKET_FILTER", "BPF_PROG_TYPE_LWT_IN",
    "BPF_PROG_TYPE_LWT_OUT", "BPF_PROG_TYPE_LWT_XMIT", "BPF_PROG_TYPE_LWT_SEG6LOCAL",
    "BPF_PROG_TYPE_FLOW_DISSECTOR", "BPF_PROG_TYPE_SK_LOOKUP", "BPF_PROG_TYPE_SK_REUSEPORT",
    "BPF_PROG_TYPE_NETFILTER",
}


def parse_bpf_prog_types(doc: Doc, lines: list[str]) -> list[Record]:
    records = []
    current_type = None
    seen: dict[str, int] = {}
    for index, line in enumerate(lines):
        if not line.startswith("|") or "Program Type" in line:
            continue
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        prog_type, attach_type, section_name, sleepable = cells[:4]
        if prog_type:
            current_type = prog_type
        if not current_type or not section_name:
            continue
        section_name = re.sub(r"\s*\[#[^\]]+\]_", "", section_name).strip("` ")
        key = f"{current_type}/{section_name}"
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            continue
        aliases = [section_name, section_name.rstrip("+"), current_type[len("BPF_PROG_TYPE_"):]]
        if attach_type:
            aliases.append(attach_type)
        records.append(
            Record(
                dataset="bpf_prog_type", key=key, doc_id=doc.sections[0].doc_id, line=index + 1,
                end_line=index + 1,
                attrs={
                    "program_type": current_type, "attach_type": attach_type or None,
                    "elf_section": section_name, "sleepable": sleepable.lower() == "yes",
                    "networking_hook": current_type in NETWORKING_PROG_TYPES,
                },
                aliases=aliases,
                text=f"{current_type} {attach_type} {section_name}",
            )
        )
    return records


def parse_bpf_map_doc(doc: Doc, lines: list[str]) -> list[Record]:
    title = doc.sections[0]
    map_types = sorted(set(re.findall(r"BPF_MAP_TYPE_[A-Z0-9_]+", title.heading)))
    if not map_types:
        map_types = sorted(set(re.findall(r"BPF_MAP_TYPE_[A-Z0-9_]+", title.text)))[:4]
    kernel_helpers: list[dict] = []
    userspace_calls: list[dict] = []
    by_id = {s.doc_id: s for s in doc.sections}

    def side_of(section: Section) -> str | None:
        current = section
        while current is not None:
            heading = current.heading.lower()
            if heading.startswith("example"):
                return None
            if "kernel" in heading:
                return "kernel"
            if "user" in heading:
                return "user"
            current = by_id.get(current.parent_doc_id) if current.parent_doc_id else None
        return None

    for section in doc.sections[1:]:
        names = re.findall(r"\b(bpf_[a-z0-9_]+)\(\)", section.heading)
        if not names:
            continue
        side = side_of(section)
        for name in names:
            entry = {"name": name, "doc_id": section.doc_id}
            if side == "user":
                userspace_calls.append(entry)
            elif side == "kernel":
                kernel_helpers.append(entry)
    summary = _first_prose(lines, title)
    records = []
    for map_type in map_types:
        records.append(
            Record(
                dataset="bpf_map_type", key=map_type, doc_id=title.doc_id, line=title.start_line,
                end_line=title.end_line,
                attrs={
                    "summary": summary, "kernel_helpers": kernel_helpers,
                    "userspace_calls": userspace_calls, "documented_with": [m for m in map_types if m != map_type],
                },
                aliases=[map_type[len("BPF_MAP_TYPE_"):], map_type[len("BPF_MAP_TYPE_"):].lower()],
                text=f"{map_type} {summary} {' '.join(h['name'] for h in kernel_helpers + userspace_calls)}",
            )
        )
    return records


def parse_kfunc_flags(doc: Doc, lines: list[str]) -> list[Record]:
    records = []
    for section in doc.sections:
        flag = re.search(r"\b(KF_[A-Z_]+) flag", section.heading)
        annotation = re.search(r"(__[a-z_]+) Annotation", section.heading)
        if not flag and not annotation:
            continue
        name = flag.group(1) if flag else annotation.group(1)
        description = _paragraph(lines, section.start_line + 1, limit=8)
        records.append(
            Record(
                dataset="kfunc_flag", key=name, doc_id=section.doc_id, line=section.start_line,
                end_line=section.end_line,
                attrs={"kind": "flag" if flag else "parameter_annotation", "description": description,
                       "defined_in": "include/linux/btf.h" if flag else None},
                text=f"{name} {description}",
            )
        )
    return records


def parse_btf_kinds(doc: Doc, lines: list[str]) -> list[Record]:
    sections = {}
    for section in doc.sections:
        match = re.search(r"\b(BTF_KIND_[A-Z0-9_]+)$", section.heading)
        if match:
            sections[match.group(1)] = section
    records = []
    for index, line in enumerate(lines):
        match = re.match(r"^\s+#define (BTF_KIND_[A-Z0-9_]+)\s+(\d+)\s+/\*\s*(.*?)\s*\*/", line)
        if not match:
            continue
        name, value, meaning = match.groups()
        section = sections.get(name) or sections.get("BTF_KIND_STRUCT" if name == "BTF_KIND_UNION" else name)
        records.append(
            Record(
                dataset="btf_kind", key=name, doc_id=(section or _section_at(doc, index + 1)).doc_id,
                line=index + 1, end_line=index + 1,
                attrs={"value": int(value), "meaning": meaning, "defined_in": "include/uapi/linux/btf.h"},
                aliases=[value, name[len("BTF_KIND_"):]],
                text=f"{name} {meaning}",
            )
        )
    return records


def _simple_table(lines: list[str], start: int) -> tuple[list[str], list[list[str]], int]:
    """Parse an RST simple table that starts at or after `start`. Returns header, rows, end."""
    index = start
    while index < len(lines) and not re.match(r"^\s*=+(\s+=+)+\s*$", lines[index]):
        index += 1
        if index - start > 6:
            return [], [], start
    if index >= len(lines):
        return [], [], start
    border = lines[index]
    spans = [(m.start(), m.end()) for m in re.finditer(r"=+", border)]

    def cells(line: str) -> list[str]:
        out = []
        for position, (begin, _) in enumerate(spans):
            stop = spans[position + 1][0] if position + 1 < len(spans) else len(line)
            out.append(line[begin:stop].strip())
        return out

    header: list[str] = []
    rows: list[list[str]] = []
    borders = 1
    index += 1
    while index < len(lines):
        line = lines[index]
        if re.match(r"^\s*=+(\s+=+)+\s*$", line):
            borders += 1
            if borders == 3:
                break
        elif line.strip():
            if borders == 1:
                header = cells(line) if not header else [f"{a} {b}".strip() for a, b in zip(header, cells(line))]
            else:
                row = cells(line)
                if rows and not row[0]:
                    rows[-1] = [f"{a} {b}".strip() for a, b in zip(rows[-1], row)]
                else:
                    rows.append(row)
        index += 1
    return header, rows, index + 1


def parse_bpf_isa(doc: Doc, lines: list[str]) -> list[Record]:
    records = []
    for index, line in enumerate(lines):
        match = re.match(r"^\s*\.\. table:: (.+)$", line)
        if not match:
            continue
        caption = match.group(1).strip()
        header, rows, end = _simple_table(lines, index + 1)
        if not rows:
            continue
        section = _section_at(doc, index + 1)
        records.append(
            Record(
                dataset="bpf_isa", key=slugify(caption), doc_id=section.doc_id, line=index + 1,
                end_line=end,
                attrs={"caption": caption, "columns": header,
                       "rows": [dict(zip(header, row)) for row in rows]},
                aliases=[row[0] for row in rows if row and row[0]],
                text=f"{caption} {' '.join(' '.join(r) for r in rows)}"[:4000],
            )
        )
    return records


# --------------------------------------------------------------------------------------


def extract_records(doc: Doc, text: str) -> list[Record]:
    lines = text.split("\n")
    path = doc.doc_path
    if path in SYSCTL_DOCS:
        return parse_sysctls(doc, lines)
    if path == "networking/snmp_counter.rst":
        return parse_snmp(doc, lines)
    if path == "networking/xfrm_proc.rst":
        return parse_xfrm_counters(doc, lines)
    if path.startswith("networking/net_cachelines/"):
        return parse_net_cachelines(doc, lines)
    if path == "networking/ethtool-netlink.rst":
        return parse_ethtool_messages(doc, lines)
    if path == "networking/operstates.rst":
        return parse_operstates(doc, lines)
    if path == "networking/proc_net_tcp.rst":
        return parse_proc_net_tcp(doc, lines)
    if path == "bpf/libbpf/program_types.rst":
        return parse_bpf_prog_types(doc, lines)
    if re.fullmatch(r"bpf/map_[a-z_]+\.rst", path):
        return parse_bpf_map_doc(doc, lines)
    if path == "bpf/kfuncs.rst":
        return parse_kfunc_flags(doc, lines)
    if path == "bpf/btf.rst":
        return parse_btf_kinds(doc, lines)
    if path == "bpf/standardization/instruction-set.rst":
        return parse_bpf_isa(doc, lines)
    return []
