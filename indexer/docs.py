"""Documentation index: files, sections, code mentions and kernel-doc directives."""

import re
from dataclasses import dataclass, field

import yaml

import scope

ADORNMENT_CHARS = set("=-~^\"'`#*+_:.<>")


@dataclass
class Section:
    doc_id: str
    doc_path: str
    heading: str
    level: int
    parent_doc_id: str | None
    start_line: int  # 1-based, inclusive
    end_line: int  # inclusive, covers subsections
    body_end_line: int  # inclusive, stops before the first subsection
    text: str = ""  # own text, used for full-text indexing and mention extraction only


@dataclass
class Mention:
    doc_id: str
    line: int
    raw_text: str
    kind: str  # function, struct, macro, path, sysctl, config, counter, netlink_msg
    name: str


@dataclass
class KernelDoc:
    doc_id: str
    source_path: str
    mode: str
    names: str
    line: int


@dataclass
class Doc:
    doc_path: str
    folder: str
    format: str
    title: str
    line_count: int
    cluster: str
    sections: list[Section] = field(default_factory=list)


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "section"


def _is_adornment(line: str) -> bool:
    stripped = line.rstrip()
    return (
        len(stripped) >= 3
        and stripped[0] in ADORNMENT_CHARS
        and stripped == stripped[0] * len(stripped)
    )


def _clean_heading(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("``", "").strip()).rstrip(":").strip()


def rst_headings(lines: list[str]) -> list[tuple[int, int, str, int]]:
    """Find headings. Returns (first_line_index, title_line_index, title, level)."""
    styles: list[tuple[str, bool]] = []
    headings = []
    index = 1
    count = len(lines)
    while index < count:
        line = lines[index]
        if _is_adornment(line):
            title = lines[index - 1]
            before = lines[index - 2] if index >= 2 else ""
            overline = index >= 2 and _is_adornment(before) and before[0] == line[0]
            title_ok = (
                title.strip()
                and not _is_adornment(title)
                and not title.lstrip().startswith("..")
                and len(line.rstrip()) >= max(3, len(title.strip()) // 2)
                and (overline or not title[0].isspace())
                and (overline or index < 2 or not before.strip() or _is_adornment(before))
            )
            if title_ok:
                style = (line[0], overline)
                if style not in styles:
                    styles.append(style)
                first = index - 2 if overline else index - 1
                headings.append((first, index - 1, _clean_heading(title), styles.index(style)))
        index += 1
    return headings


def txt_headings(lines: list[str]) -> list[tuple[int, int, str, int]]:
    """Numbered headings in plain-text drafts: "3.4.2    TAG TYPE 1"."""
    headings = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\d+(?:\.\d+)*)\.?\s{1,6}([A-Z][^\n]{2,70})$", line)
        blank_before = index == 0 or not lines[index - 1].strip()
        if match and blank_before and not line.rstrip().endswith((".", ",")):
            level = match.group(1).count(".") + 1
            headings.append((index, index, f"{match.group(1)} {match.group(2).strip()}", level))
    return headings


def _build_sections(doc_path: str, lines: list[str], headings, fallback_title: str) -> list[Section]:
    total = len(lines)
    if not headings:
        return [
            Section(
                doc_id=f"{doc_path}#document", doc_path=doc_path, heading=fallback_title, level=0,
                parent_doc_id=None, start_line=1, end_line=total, body_end_line=total,
                text="\n".join(lines),
            )
        ]
    sections: list[Section] = []
    used: dict[str, int] = {}
    stack: list[Section] = []
    for position, (first, _, title, level) in enumerate(headings):
        slug = slugify(title)
        used[slug] = used.get(slug, 0) + 1
        if used[slug] > 1:
            slug = f"{slug}-{used[slug]}"
        end = total
        for later_first, _, _, later_level in headings[position + 1 :]:
            if later_level <= level:
                end = later_first
                break
        body_end = headings[position + 1][0] if position + 1 < len(headings) else total
        while stack and stack[-1].level >= level:
            stack.pop()
        section = Section(
            doc_id=f"{doc_path}#{slug}", doc_path=doc_path, heading=title, level=level,
            parent_doc_id=stack[-1].doc_id if stack else None,
            start_line=first + 1, end_line=end, body_end_line=body_end,
            text="\n".join(lines[first:body_end]),
        )
        stack.append(section)
        sections.append(section)
    # The first heading of a file is its title: it owns everything before it too.
    sections[0].start_line = 1
    return sections


def parse_doc(doc_path: str, text: str) -> Doc:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    fmt = scope.doc_format(doc_path)
    folder = doc_path.split("/", 1)[0]
    stem = doc_path.rsplit("/", 1)[-1]
    if fmt == "yaml":
        sections, title = yaml_sections(doc_path, text, lines)
    else:
        headings = rst_headings(lines) if fmt == "rst" else txt_headings(lines)
        title = headings[0][2] if headings and fmt == "rst" else stem
        if fmt == "txt":
            # a plain-text file gets a whole-file section above its numbered sections
            whole = Section(
                doc_id=f"{doc_path}#document", doc_path=doc_path, heading=stem, level=0,
                parent_doc_id=None, start_line=1, end_line=len(lines),
                body_end_line=(headings[0][0] if headings else len(lines)),
                text="\n".join(lines[: headings[0][0]] if headings else lines),
            )
            sections = [whole]
            if headings:
                numbered = _build_sections(doc_path, lines, headings, stem)
                numbered[0].start_line = headings[0][0] + 1
                for section in numbered:
                    section.level += 1
                    section.parent_doc_id = section.parent_doc_id or whole.doc_id
                sections += numbered
        else:
            sections = _build_sections(doc_path, lines, headings, stem)
    return Doc(
        doc_path=doc_path, folder=folder, format=fmt, title=title, line_count=len(lines),
        cluster=scope.doc_cluster(doc_path), sections=sections,
    )


# --------------------------------------------------------------------------------------
# YAML netlink specs: sections per family, operation, attribute set and definition
# --------------------------------------------------------------------------------------


def _mapping_items(node) -> dict:
    if not isinstance(node, yaml.MappingNode):
        return {}
    return {key.value: value for key, value in node.value}


def _node_range(node, lines: list[str]) -> tuple[int, int]:
    """1-based inclusive line range of a YAML node. A block node's end mark sits on the
    token after it, so trailing blank lines and a dangling "-" are trimmed."""
    start = node.start_mark.line + 1
    end = max(start, node.end_mark.line if node.end_mark.column == 0 or node.end_mark.line > node.start_mark.line else start)
    end = min(end, len(lines))
    while end > start and lines[end - 1].strip() in ("", "-"):
        end -= 1
    return start, end


def yaml_sections(doc_path: str, text: str, lines: list[str]) -> tuple[list[Section], str]:
    total = len(lines)
    stem = doc_path.rsplit("/", 1)[-1]
    whole = Section(
        doc_id=f"{doc_path}#spec", doc_path=doc_path, heading=stem, level=0, parent_doc_id=None,
        start_line=1, end_line=total, body_end_line=total, text="",
    )
    if "/specs/" not in doc_path:
        whole.text = text  # a schema file: one section
        return [whole], stem
    root = _mapping_items(yaml.compose(text))
    data = yaml.safe_load(text)
    title = f"{data.get('name', stem)} netlink family"
    whole.heading = title
    whole.text = f"{data.get('name', '')} {data.get('doc', '')} {data.get('protocol', '')}"
    sections = [whole]
    first_child_line = total + 1

    def add(kind: str, name: str, node, summary: str) -> None:
        nonlocal first_child_line
        start, end = _node_range(node, lines)
        # a sequence item starts at its "-" line when that sits alone above the mapping
        if start >= 2 and lines[start - 2].strip() == "-":
            start -= 1
        first_child_line = min(first_child_line, start)
        sections.append(
            Section(
                doc_id=f"{doc_path}#{kind}/{name}", doc_path=doc_path, heading=f"{kind} {name}",
                level=1, parent_doc_id=whole.doc_id, start_line=start, end_line=end,
                body_end_line=end, text=summary,
            )
        )

    definitions = root.get("definitions")
    if isinstance(definitions, yaml.SequenceNode):
        for node, item in zip(definitions.value, data.get("definitions") or []):
            entries = item.get("entries") or item.get("members") or []
            names = " ".join(str(e.get("name", "")) if isinstance(e, dict) else str(e) for e in entries)
            add("definition", item["name"], node, f"{item['name']} {item.get('type', '')} {item.get('doc', '')} {names}")
    attribute_sets = root.get("attribute-sets")
    if isinstance(attribute_sets, yaml.SequenceNode):
        for node, item in zip(attribute_sets.value, data.get("attribute-sets") or []):
            attrs = item.get("attributes") or []
            summary = " ".join(f"{a.get('name', '')} {a.get('doc', '')}" for a in attrs)
            add("attr-set", item["name"], node, f"{item['name']} {item.get('doc', '')} {summary}")
    operations = _mapping_items(root.get("operations")).get("list")
    if isinstance(operations, yaml.SequenceNode):
        for node, item in zip(operations.value, (data.get("operations") or {}).get("list") or []):
            add("op", item["name"], node, f"{item['name']} {item.get('doc', '')} {item.get('attribute-set', '')}")
    whole.body_end_line = max(1, first_child_line - 1)
    return sections, title


# --------------------------------------------------------------------------------------
# Mentions of code in prose
# --------------------------------------------------------------------------------------

_FUNCTION_RE = re.compile(r"(?<![\w.>/-])([A-Za-z_][A-Za-z0-9_]{2,})\(\)")
_STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]{2,})\b")
_CONSTANT_RE = re.compile(r"(?<![\w/.-])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b(?!\()")
_PATH_RE = re.compile(
    r"(?<![\w/.-])((?:net|include|drivers|kernel|lib|tools|Documentation|fs|arch|security|"
    r"samples|scripts|mm|crypto|block|init|ipc|sound|virt)/[A-Za-z0-9_./+-]*[A-Za-z0-9_/])"
)
_PROC_SYS_RE = re.compile(r"/proc/sys/(net/[A-Za-z0-9_/.-]*[A-Za-z0-9_])")
_KERNEL_DOC_RE = re.compile(r"^\s*\.\. kernel-doc::\s*(\S+)\s*$")
_OPTION_RE = re.compile(r"^\s+:([a-z-]+):\s*(.*)$")
_NETLINK_MSG_RE = re.compile(r"^(RTM_|NLMSG_|[A-Z0-9]+_CMD_|ETHTOOL_MSG_|NFT_MSG_|IPSET_CMD_|TCA_|IFLA_|RTA_)")


def extract_mentions(section: Section) -> tuple[list[Mention], list[KernelDoc]]:
    mentions: list[Mention] = []
    kernel_docs: list[KernelDoc] = []
    seen: set[tuple[str, str]] = set()

    def add(line_number: int, raw: str, kind: str, name: str) -> None:
        if (kind, name) in seen:
            return
        seen.add((kind, name))
        mentions.append(Mention(section.doc_id, line_number, raw, kind, name))

    if section.doc_path.endswith(".yaml"):
        return mentions, kernel_docs  # specs are structured data, not prose
    lines = section.text.split("\n")
    for offset, line in enumerate(lines):
        line_number = section.start_line + offset
        directive = _KERNEL_DOC_RE.match(line)
        if directive:
            mode, names = "all", ""
            for option_line in lines[offset + 1 : offset + 6]:
                option = _OPTION_RE.match(option_line)
                if not option:
                    break
                if option.group(1) in ("functions", "identifiers", "internal", "export", "doc"):
                    mode, names = option.group(1), option.group(2).strip()
                    break
            kernel_docs.append(KernelDoc(section.doc_id, directive.group(1), mode, names, line_number))
            add(line_number, directive.group(1), "path", directive.group(1))
            continue
        for match in _FUNCTION_RE.finditer(line):
            add(line_number, match.group(0), "function", match.group(1))
        for match in _STRUCT_RE.finditer(line):
            add(line_number, match.group(0), "struct", match.group(1))
        for match in _PROC_SYS_RE.finditer(line):
            add(line_number, match.group(0), "sysctl", match.group(1).rstrip("/").replace("/", "."))
        for match in _PATH_RE.finditer(line):
            path = match.group(1).rstrip(".")
            is_file = re.search(r"\.(c|h|S|rst|txt|yaml|py|sh|json)$", path) is not None
            is_folder = match.group(1).endswith("/") and path.count("/") >= 2
            if is_file or is_folder:
                add(line_number, match.group(0), "path", path)
        for match in _CONSTANT_RE.finditer(line):
            name = match.group(1)
            if name.startswith("CONFIG_"):
                add(line_number, name, "config", name)
            elif _NETLINK_MSG_RE.match(name):
                add(line_number, name, "netlink_msg", name)
            elif len(name) >= 5:
                add(line_number, name, "macro", name)
    return mentions, kernel_docs
