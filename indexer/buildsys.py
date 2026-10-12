"""Kconfig, Makefile and MAINTAINERS parsing."""

import posixpath
import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------------------
# Kconfig
# --------------------------------------------------------------------------------------

_KCONFIG_TYPES = ("bool", "tristate", "int", "hex", "string", "def_bool", "def_tristate")


@dataclass
class KconfigOption:
    name: str  # CONFIG_X
    path: str
    line: int
    end_line: int
    value_type: str | None = None
    prompt: str | None = None
    defaults: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    selects: list[str] = field(default_factory=list)
    implies: list[str] = field(default_factory=list)
    help: str = ""


def parse_kconfig(path: str, text: str) -> list[KconfigOption]:
    options: list[KconfigOption] = []
    current: KconfigOption | None = None
    in_help = False
    help_indent = None
    help_lines: list[str] = []
    lines = text.split("\n")

    def finish(end_line: int) -> None:
        nonlocal current, in_help, help_indent, help_lines
        if current is not None:
            current.help = " ".join(" ".join(help_lines).split())
            current.end_line = end_line
            options.append(current)
        current, in_help, help_indent, help_lines = None, False, None, []

    for index, raw in enumerate(lines):
        line = raw.expandtabs(8)
        stripped = line.strip()
        if in_help:
            indent = len(line) - len(line.lstrip())
            if not stripped:
                help_lines.append("")
                continue
            if help_indent is None:
                help_indent = indent
            if indent >= help_indent:
                help_lines.append(stripped)
                continue
            in_help = False
        match = re.match(r"^(?:menu)?config\s+(\w+)\s*$", stripped)
        if match and not raw[:1].isspace():
            last = index
            while last > 0 and not lines[last - 1].strip():
                last -= 1
            finish(last)
            current = KconfigOption(name=f"CONFIG_{match.group(1)}", path=path, line=index + 1, end_line=index + 1)
            continue
        if current is None:
            continue
        if not raw[:1].isspace() and stripped and not stripped.startswith("#"):
            last = index
            while last > 0 and not lines[last - 1].strip():
                last -= 1
            finish(last)
            continue
        word = stripped.split(None, 1)[0] if stripped else ""
        rest = stripped[len(word):].strip()
        if word in _KCONFIG_TYPES:
            current.value_type = word.replace("def_", "")
            prompt = re.match(r'"((?:\\.|[^"])*)"', rest)
            if prompt:
                current.prompt = prompt.group(1)
            elif word.startswith("def_") and rest:
                current.defaults.append(rest)
        elif word == "prompt":
            prompt = re.match(r'"((?:\\.|[^"])*)"', rest)
            if prompt:
                current.prompt = prompt.group(1)
        elif word == "default":
            current.defaults.append(rest)
        elif word == "depends" and rest.startswith("on"):
            current.depends_on.append(rest[2:].strip())
        elif word == "select":
            current.selects.append(rest)
        elif word == "imply":
            current.implies.append(rest)
        elif word in ("help", "---help---"):
            in_help, help_indent, help_lines = True, None, []
    finish(len(lines))
    return options


# --------------------------------------------------------------------------------------
# Makefiles: which CONFIG option builds which file
# --------------------------------------------------------------------------------------

_ASSIGN_RE = re.compile(r"^([A-Za-z0-9_.-]+?)-(y|m|objs|\$\((CONFIG_\w+)\))\s*(?::=|\+=|=)\s*(.*)$")


def _logical_lines(text: str) -> list[str]:
    joined = re.sub(r"\\\n", " ", text)
    return [re.sub(r"\s+#.*$", "", line).strip() for line in joined.split("\n")]


def parse_makefile(text: str) -> tuple[dict[str, str | None], dict[str, list[tuple[str, str | None]]]]:
    """Returns (obj targets -> config or None for always, composite name -> [(part, config)])."""
    targets: dict[str, str | None] = {}
    composites: dict[str, list[tuple[str, str | None]]] = {}
    for line in _logical_lines(text):
        match = _ASSIGN_RE.match(line)
        if not match:
            continue
        name, _, config, value = match.groups()
        words = [w for w in value.split() if not w.startswith("$")]
        if name == "obj":
            for word in words:
                if config is None:
                    targets[word] = None  # built unconditionally
                else:
                    targets.setdefault(word, config)
        elif name not in ("ccflags", "asflags", "subdir", "always", "extra", "hostprogs", "userprogs", "targets", "clean", "CFLAGS"):
            composites.setdefault(name, []).extend((word, config) for word in words)
    return targets, composites


def file_configs(makefiles: dict[str, str], files: set[str]) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Map each source file to the CONFIG option that builds it, and each option to its files.

    makefiles maps a Makefile path to its text. A folder inherits the option that the parent
    Makefile uses to descend into it.
    """
    parsed = {posixpath.dirname(path): parse_makefile(text) for path, text in makefiles.items()}
    folder_config: dict[str, str | None] = {}

    def config_of_folder(folder: str) -> str | None:
        if folder in folder_config:
            return folder_config[folder]
        folder_config[folder] = None  # guards against cycles
        parent = posixpath.dirname(folder)
        result = None
        if parent in parsed:
            targets, _ = parsed[parent]
            name = posixpath.basename(folder) + "/"
            if name in targets:
                result = targets[name] or config_of_folder(parent)
        elif parent:
            result = config_of_folder(parent) if parent in folder_config else None
        folder_config[folder] = result
        return result

    by_file: dict[str, str] = {}
    by_config: dict[str, list[str]] = {}

    def assign(folder: str, obj: str, config: str | None, composites, depth: int = 0) -> None:
        if not obj.endswith(".o") or depth > 4:
            return
        stem = obj[: -len(".o")]
        effective = config or config_of_folder(folder)
        if stem in composites:
            for part, part_config in composites[stem]:
                assign(folder, part, part_config or config, composites, depth + 1)
        source = posixpath.normpath(posixpath.join(folder, stem + ".c"))
        if source in files and effective and source not in by_file:
            by_file[source] = effective
            by_config.setdefault(effective, []).append(source)

    for folder, (targets, composites) in parsed.items():
        for obj, config in targets.items():
            assign(folder, obj, config, composites)
    return by_file, by_config


# --------------------------------------------------------------------------------------
# MAINTAINERS
# --------------------------------------------------------------------------------------


@dataclass
class MaintainerSection:
    name: str
    files: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    name_patterns: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    status: str | None = None


def parse_maintainers(text: str) -> list[MaintainerSection]:
    lines = text.split("\n")
    start = next((i for i, l in enumerate(lines) if l.startswith("Maintainers List")), 0)
    sections: list[MaintainerSection] = []
    current: MaintainerSection | None = None
    for line in lines[start + 2 :]:
        if not line.strip():
            current = None
            continue
        tagged = re.match(r"^([A-Z]):\s*(.*)$", line)
        if tagged and current is not None:
            tag, value = tagged.groups()
            if tag == "F":
                current.files.append(value.strip())
            elif tag == "X":
                current.excludes.append(value.strip())
            elif tag == "N":
                current.name_patterns.append(value.strip())
            elif tag == "K":
                current.keywords.append(value.strip())
            elif tag == "S":
                current.status = value.strip()
        elif not tagged and not line[:1].isspace() and current is None:
            current = MaintainerSection(name=line.strip())
            sections.append(current)
    return [s for s in sections if s.files or s.name_patterns]


def _pattern_regex(pattern: str) -> re.Pattern:
    body = "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in pattern)
    if pattern.endswith("/"):
        return re.compile("^" + body)
    return re.compile("^" + body + "(?:$|/)")


def maintainers_for(sections: list[MaintainerSection], paths: list[str]) -> dict[str, list[str]]:
    """Section names covering each path, most specific first."""
    compiled = []
    roots = {p.split("/", 1)[0] for p in paths}
    for section in sections:
        relevant = [f for f in section.files if f.split("/", 1)[0] in roots or f[:1] in "*?"]
        if not relevant and not section.name_patterns:
            continue
        names = []
        for pattern in section.name_patterns:
            try:
                names.append(re.compile(pattern))
            except re.error:
                continue
        compiled.append(
            (
                section.name,
                [(f, _pattern_regex(f)) for f in relevant],
                [_pattern_regex(x) for x in section.excludes],
                names,
            )
        )
    result: dict[str, list[str]] = {}
    for path in paths:
        hits = []
        for name, includes, excludes, names in compiled:
            best = max((len(f) for f, regex in includes if regex.match(path)), default=0)
            if not best and any(regex.search(path) for regex in names):
                best = 1
            if best and not any(regex.match(path) for regex in excludes):
                hits.append((best, name))
        hits.sort(key=lambda hit: (-hit[0], hit[1]))
        result[path] = [name for _, name in hits[:6]]
    return result
