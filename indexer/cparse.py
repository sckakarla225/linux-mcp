"""Symbol extraction from kernel C sources with tree-sitter.

A plain C parser does not understand the kernel's annotation macros (`__init`, `__rcu`,
`__must_check`, ...) or its function-defining macros (`BPF_CALL_2`, `SYSCALL_DEFINE3`,
`DEFINE_MUTEX`, ...). Two rules cover that:

- annotation macros are blanked out with spaces before parsing, which keeps every byte offset
  and line number intact;
- a top-level macro call followed by a `{ ... }` block is a macro-generated function, and
  `DEFINE_*`-style macro calls define globals.
"""

import re
from dataclasses import dataclass, field

import tree_sitter_c
from tree_sitter import Language, Node, Parser

_PARSER = Parser(Language(tree_sitter_c.language()))

# Annotations with no arguments.
_BARE_ANNOTATIONS = [
    "__init", "__exit", "__net_init", "__net_exit", "__net_initdata", "__net_initconst",
    "__initdata", "__initconst", "__exitdata", "__init_or_module", "__meminit", "__ref",
    "__refdata", "__read_mostly", "__ro_after_init", "__randomize_layout",
    "__no_randomize_layout", "__packed", "____cacheline_aligned_in_smp",
    "____cacheline_aligned", "__cacheline_aligned_in_smp", "__cacheline_aligned",
    "____cacheline_internodealigned_in_smp", "__percpu", "__rcu", "__user", "__kernel",
    "__iomem", "__force", "__bitwise", "__must_check", "__always_unused", "__maybe_unused",
    "__used", "__unused", "__weak", "__deprecated", "__sched", "__latent_entropy", "notrace",
    "noinline_for_stack", "noinline", "__noreturn", "__malloc", "__flatten", "__hot",
    "__cold", "__pure", "__private", "__nocast", "__safe", "__nonstring",
    "__designated_init", "__always_inline", "__attribute_const__", "__lockfunc",
    "__visible", "__nocfi", "noinstr", "__no_kcsan", "__no_profile", "asmlinkage",
    "__bpf_kfunc", "INDIRECT_CALLABLE_SCOPE", "__inline__", "__inline", "__no_sanitize_address",
    "__no_stack_protector", "__cpuidle", "__kprobes", "__sum16_unused", "__ksym",
    "__rcu_dereference_unused", "__read_once_size_unused", "__nullable", "__ign",
    "__counted_by_ptr_unused", "BPF_INDIRECT_CALLABLE_UNUSED", "__initdata_or_module",
    "__ipv6_mod_unused", "__net_exit_data",
]
# Annotations that take a parenthesised argument list.
_ARG_ANNOTATIONS = [
    "__acquires", "__releases", "__must_hold", "__cond_acquires", "__printf", "__scanf",
    "__aligned", "__counted_by_le", "__counted_by_be", "__counted_by", "__section",
    "__alloc_size", "__nonnull", "__realloc_size", "__diagnose_as", "__no_sanitize",
    "__assume_aligned", "__exception", "__guarded_by", "__sized_by",
]
# Struct-body statements that are bookkeeping, not members.
_STATEMENT_ANNOTATIONS = [
    "__cacheline_group_begin_aligned", "__cacheline_group_end_aligned",
    "__cacheline_group_begin", "__cacheline_group_end",
]

_BARE_RE = re.compile(rb"\b(" + b"|".join(a.encode() for a in _BARE_ANNOTATIONS) + rb")\b")
_ARG_RE = re.compile(
    rb"\b(" + b"|".join(a.encode() for a in _ARG_ANNOTATIONS) + rb")\s*\((?:[^()]|\([^()]*\))*\)"
)
_STATEMENT_RE = re.compile(
    rb"\b("
    + b"|".join(a.encode() for a in _STATEMENT_ANNOTATIONS)
    + rb")\s*\((?:[^()]|\([^()]*\))*\)\s*;"
)


def _blank(match: re.Match) -> bytes:
    return re.sub(rb"[^\n]", b" ", match.group(0))


def blank_annotations(source: bytes) -> bytes:
    """Replace kernel annotation macros with spaces, preserving offsets and newlines."""
    source = _STATEMENT_RE.sub(_blank, source)
    source = _ARG_RE.sub(_blank, source)
    return _BARE_RE.sub(_blank, source)


# Macros that define a function when followed by a body.
FUNCTION_MACRO_RE = re.compile(
    r"^(BPF_CALL_\d|SYSCALL_DEFINE\d|COMPAT_SYSCALL_DEFINE\d|__bpf_kfunc_start_defs|"
    r"DEFINE_BPF_ITER_FUNC|BPF_STRUCT_OPS|BPF_STRUCT_OPS_SLEEPABLE|"
    r"TC_INDIRECT_SCOPE|DEFINE_SIMPLE_ATTRIBUTE)$"
)
# Macros that define a global variable; the argument index holding the name.
GLOBAL_MACROS = {
    "DEFINE_MUTEX": 0, "DEFINE_SPINLOCK": 0, "DEFINE_RWLOCK": 0, "DEFINE_RAW_SPINLOCK": 0,
    "DEFINE_SEQLOCK": 0, "DEFINE_RWSEM": 0, "DEFINE_IDA": 0, "DEFINE_IDR": 0,
    "DEFINE_XARRAY": 0, "DEFINE_XARRAY_ALLOC": 0, "DEFINE_XARRAY_ALLOC1": 0,
    "DEFINE_XARRAY_FLAGS": 0, "DEFINE_PER_CPU": 1, "DEFINE_PER_CPU_ALIGNED": 1,
    "DEFINE_PER_CPU_READ_MOSTLY": 1, "DEFINE_PER_CPU_SHARED_ALIGNED": 1,
    "DEFINE_STATIC_KEY_FALSE": 0, "DEFINE_STATIC_KEY_TRUE": 0,
    "DEFINE_STATIC_KEY_FALSE_RO": 0, "DEFINE_STATIC_KEY_TRUE_RO": 0,
    "DEFINE_STATIC_KEY_ARRAY_FALSE": 0, "DEFINE_STATIC_SRCU": 0, "DEFINE_SRCU": 0,
    "DEFINE_HASHTABLE": 0, "DEFINE_READ_MOSTLY_HASHTABLE": 0, "DEFINE_WAIT_OVERRIDE_MAP": 0,
    "DECLARE_BITMAP": 0, "DECLARE_WORK": 0, "DECLARE_DELAYED_WORK": 0,
    "DECLARE_DEFERRABLE_WORK": 0, "DECLARE_RWSEM": 0, "DECLARE_WAIT_QUEUE_HEAD": 0,
    "DECLARE_COMPLETION": 0, "DECLARE_TASKLET": 0, "DECLARE_TASKLET_OLD": 0,
    "LIST_HEAD": 0, "HLIST_HEAD": 0, "BLOCKING_NOTIFIER_HEAD": 0, "ATOMIC_NOTIFIER_HEAD": 0,
    "RAW_NOTIFIER_HEAD": 0, "SRCU_NOTIFIER_HEAD": 0, "DEFINE_RATELIMIT_STATE": 0,
    "DEFINE_STATIC_CALL": 0, "DEFINE_STATIC_CALL_NULL": 0, "DEFINE_STATIC_CALL_RET0": 0,
    "DEFINE_BPF_DISPATCHER": 0, "DEFINE_SNMP_STAT": 1, "DEFINE_KFIFO": 0,
    "DEFINE_TIMER": 0, "DEFINE_WAIT": 0, "BTF_ID_LIST": 0, "BTF_ID_LIST_SINGLE": 0,
    "BTF_ID_LIST_GLOBAL": 0, "BTF_ID_LIST_GLOBAL_SINGLE": 0, "BTF_SET_START": 0,
    "BTF_SET8_START": 0, "BTF_KFUNCS_START": 0, "DEFINE_COOKIE": 0,
    "DEFINE_DEBUGFS_ATTRIBUTE": 0, "DEFINE_SHOW_ATTRIBUTE": 0, "DEFINE_PROC_SHOW_ATTRIBUTE": 0,
    "DEFINE_FREE": 0, "DEFINE_NFT_CHAIN_STAT": 0, "DEFINE_LOCK_GUARD_1": 0,
}
_GLOBAL_MACRO_RE = re.compile(
    r"^(?P<static>static\s+)?(?P<macro>(?:DEFINE|DECLARE)_[A-Z0-9_]+|"
    + "|".join(sorted((m for m in GLOBAL_MACROS if not m.startswith(("DEFINE_", "DECLARE_"))), key=len, reverse=True))
    + r")\s*\((?P<args>[^;{]*?)\)\s*(?:=|;|$)",
    re.MULTILINE,
)
# DECLARE_* macros that only declare something defined elsewhere.
_DECLARATION_ONLY_RE = re.compile(
    r"^DECLARE_(PER_CPU\w*|STATIC_KEY_\w+|STATIC_CALL|EVENT_CLASS|TRACE\w*|BPF_DISPATCHER|"
    r"SNMP_STAT|INDIRECT_CALLABLE\w*|SOCKADDR|FLEX_ARRAY|KFIFO_PTR|HASHTABLE|RAW_FLEX|"
    r"NET_REFTRACKER|ETHTOOL\w*|PHY_INTERFACE_MASK|LINK_MODE_MASK|CRYPTO_WAIT|"
    r"MAC_BUF|STATIC_KEY\w*|STATIC_CALL\w*|RWSEM_UNUSED)$"
)
_FUNCTION_MACRO_LINE_RE = re.compile(
    r"^(?P<static>static\s+)?(?P<macro>BPF_CALL_\d|SYSCALL_DEFINE\d|COMPAT_SYSCALL_DEFINE\d)"
    r"\s*\(\s*(?P<name>\w+)",
    re.MULTILINE,
)
# Kernel style: a function header starting in column 0, then "{" alone in column 0.
_STYLE_FUNCTION_RE = re.compile(
    r"^(?P<head>[A-Za-z_][^\n;{}#=]*?\b(?P<name>[A-Za-z_]\w*)\s*\((?:[^;{}()]|\([^;{}()]*\))*\))\s*\n\{",
    re.MULTILINE,
)
_C_KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "do", "else", "typeof"}

PREPROC_BRANCHES = {"preproc_ifdef", "preproc_if", "preproc_else", "preproc_elif", "preproc_elifdef"}
TYPE_SPECIFIERS = {"struct_specifier": "struct", "union_specifier": "union", "enum_specifier": "enum"}


@dataclass
class Symbol:
    name: str
    kind: str
    start_line: int  # 1-based; includes an attached comment block
    end_line: int
    name_line: int  # line holding the defining occurrence of the name
    signature: str
    is_static: bool = False
    is_macro_generated: bool = False
    ifdef_guard: str | None = None
    doc_comment: str | None = None
    struct_type: str | None = None  # for globals: the struct/union type, if any
    has_initializer: bool = False
    parent: str | None = None  # for enum constants: the enclosing enum name
    extra: dict = field(default_factory=dict)


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _squash(text: str, limit: int = 300) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _declarator_name(node: Node | None) -> Node | None:
    """Follow nested declarators down to the identifier being declared."""
    while node is not None:
        if node.type in ("identifier", "type_identifier", "field_identifier"):
            return node
        inner = node.child_by_field_name("declarator")
        if inner is None:
            # parenthesized_declarator and attribute wrappers hold the declarator as a child
            inner = next(
                (c for c in node.named_children if "declarator" in c.type or c.type == "identifier"),
                None,
            )
        node = inner
    return None


def _has_function_declarator(node: Node | None) -> bool:
    """True when the declarator declares a function (not a pointer to one)."""
    while node is not None:
        if node.type == "function_declarator":
            inner = node.child_by_field_name("declarator")
            return inner is not None and inner.type != "parenthesized_declarator"
        if node.type in ("identifier", "type_identifier"):
            return False
        node = node.child_by_field_name("declarator")
    return False


def _storage(node: Node, source: bytes) -> set[str]:
    return {
        _text(c, source) for c in node.children if c.type == "storage_class_specifier"
    }


def _negate(condition: str | None) -> str | None:
    if not condition:
        return None
    if re.fullmatch(r"\w+", condition):
        return f"!defined({condition})"
    positive = re.fullmatch(r"!defined\((\w+)\)", condition)
    if positive:
        return positive.group(1)
    return f"!({condition})"


class _Extractor:
    def __init__(self, source: bytes, original: bytes):
        self.source = source  # blanked
        self.original = original
        self.symbols: list[Symbol] = []
        self.error_nodes = 0
        self.include_guards: set[str] = set()

    # ---- helpers ----

    def _attached_comment(self, node: Node) -> tuple[int, str | None]:
        """Start line (1-based) including a comment block that ends right above the node."""
        start_row = node.start_point[0]
        doc = None
        prev = node.prev_sibling
        if prev is not None and prev.type == "comment" and prev.end_point[0] == start_row - 1:
            text = self.original[prev.start_byte : prev.end_byte].decode("utf-8", errors="replace")
            if text.startswith("/*"):
                start_row = prev.start_point[0]
                if text.startswith("/**"):
                    doc = text
        return start_row + 1, doc

    def _add(self, node: Node, name_node: Node, kind: str, signature: str, guard, **kw) -> Symbol:
        start_line, doc = self._attached_comment(kw.pop("comment_anchor", node))
        end_node = kw.pop("end_node", node)
        end_row = end_node.end_point[0]
        if end_node.end_point[1] == 0 and end_row > end_node.start_point[0]:
            end_row -= 1
        symbol = Symbol(
            name=_text(name_node, self.source),
            kind=kind,
            start_line=start_line,
            end_line=end_row + 1,
            name_line=name_node.start_point[0] + 1,
            signature=_squash(signature),
            ifdef_guard=guard,
            doc_comment=doc,
            **kw,
        )
        self.symbols.append(symbol)
        return symbol

    def _guard_for(self, node: Node, parent_guard: str | None, own: str | None) -> str | None:
        if own is None:
            return parent_guard
        return f"{parent_guard} && {own}" if parent_guard else own

    # ---- type specifiers ----

    def _type_specifier(self, spec: Node, outer: Node, guard) -> None:
        """Record a struct/union/enum that has a body, and its enum constants."""
        body = spec.child_by_field_name("body")
        if body is None:
            return
        kind = TYPE_SPECIFIERS[spec.type]
        name_node = spec.child_by_field_name("name")
        tag = _text(name_node, self.source) if name_node is not None else None
        if name_node is not None:
            self._add(outer, name_node, kind, f"{kind} {tag}", guard)
        if kind == "enum":
            for enumerator in body.named_children:
                if enumerator.type != "enumerator":
                    continue
                const = enumerator.child_by_field_name("name")
                if const is None:
                    continue
                self._add(
                    enumerator, const, "enum_constant",
                    f"enum {tag or '{...}'} :: {_text(enumerator, self.source)}",
                    guard, parent=tag,
                )

    def _find_type_specifier(self, node: Node) -> Node | None:
        type_node = node.child_by_field_name("type")
        if type_node is not None and type_node.type in TYPE_SPECIFIERS:
            return type_node
        return None

    # ---- top-level walk ----

    def walk(self, parent: Node, guard: str | None, depth: int = 0,
             outer: str | None = None, condition: str | None = None) -> None:
        """Visit file-scope nodes. `guard` is the #if condition in force; for a branch node,
        `outer` is the guard outside it and `condition` what its #if tested, so that an
        #else or #elif child can be recorded as the negation rather than nested inside it."""
        children = parent.children
        for index, node in enumerate(children):
            kind = node.type
            if kind in ("preproc_ifdef", "preproc_if"):
                tested = self._branch_condition(node, depth)
                self.walk(node, self._guard_for(node, guard, tested), depth + 1, guard, tested)
            elif kind in ("preproc_else", "preproc_elif", "preproc_elifdef"):
                negated = _negate(condition)
                own = None if kind == "preproc_else" else self._branch_condition(node, depth)
                branch_guard = self._guard_for(node, self._guard_for(node, outer, negated), own)
                still_false = " || ".join(c for c in (condition, own) if c) or None
                self.walk(node, branch_guard, depth + 1, outer, still_false)
            elif kind == "function_definition":
                self._function(node, guard)
            elif kind == "declaration":
                self._declaration(node, guard)
            elif kind in TYPE_SPECIFIERS:
                self._type_specifier(node, node, guard)
            elif kind == "type_definition":
                self._typedef(node, guard)
            elif kind == "preproc_def":
                name = node.child_by_field_name("name")
                is_include_guard = (
                    name is not None
                    and _text(name, self.source) in self.include_guards
                    and node.child_by_field_name("value") is None
                )
                if name is not None and not is_include_guard:
                    self._add(node, name, "macro", "#define " + _text(node, self.source)[7:].strip(), guard)
            elif kind == "preproc_function_def":
                name = node.child_by_field_name("name")
                params = node.child_by_field_name("parameters")
                if name is not None:
                    signature = "#define " + _text(name, self.source)
                    if params is not None:
                        signature += _text(params, self.source)
                    self._add(node, name, "macro", signature, guard)
            elif kind == "expression_statement":
                self._macro_function(node, children, index, guard)
            elif kind == "linkage_specification":
                body = node.child_by_field_name("body")
                if body is not None:
                    self.walk(body, guard, depth)
            elif kind == "ERROR":
                self.error_nodes += 1
                self.walk(node, guard, depth)

    def _branch_condition(self, node: Node, depth: int) -> str | None:
        first_line = _text(node, self.source).split("\n", 1)[0].strip()
        if node.type == "preproc_ifdef":
            name = node.child_by_field_name("name")
            if name is None:
                return None
            macro = _text(name, self.source)
            if first_line.startswith("#ifndef"):
                # an include guard: #ifndef X immediately followed by #define X
                following = name.next_named_sibling
                if (
                    following is not None
                    and following.type == "preproc_def"
                    and (n := following.child_by_field_name("name")) is not None
                    and _text(n, self.source) == macro
                ):
                    self.include_guards.add(macro)
                    return None
                return f"!defined({macro})"
            return macro
        if node.type == "preproc_if":
            condition = node.child_by_field_name("condition")
            return _squash(_text(condition, self.source), 120) if condition is not None else None
        if node.type in ("preproc_elif", "preproc_elifdef"):
            condition = node.child_by_field_name("condition") or node.child_by_field_name("name")
            return _squash(_text(condition, self.source), 120) if condition is not None else None
        return None

    def _function(self, node: Node, guard) -> None:
        declarator = node.child_by_field_name("declarator")
        name = _declarator_name(declarator)
        body = node.child_by_field_name("body")
        if name is None:
            return
        end = body.start_byte if body is not None else node.end_byte
        signature = self.source[node.start_byte : end].decode("utf-8", errors="replace")
        self._add(
            node, name, "function", signature, guard,
            is_static="static" in _storage(node, self.source),
        )

    def _macro_function(self, node: Node, siblings: list[Node], index: int, guard) -> None:
        call = node.named_children[0] if node.named_children else None
        if call is None or call.type != "call_expression":
            return
        function = call.child_by_field_name("function")
        arguments = call.child_by_field_name("arguments")
        if function is None or arguments is None or function.type != "identifier":
            return
        macro = _text(function, self.source)
        following = siblings[index + 1] if index + 1 < len(siblings) else None
        if not FUNCTION_MACRO_RE.match(macro) or following is None or following.type != "compound_statement":
            return
        first = arguments.named_children[0] if arguments.named_children else None
        if first is None or first.type != "identifier":
            return
        self._add(
            node, first, "function", _text(call, self.source), guard,
            is_macro_generated=True, end_node=following, extra={"macro": macro},
        )

    def _typedef(self, node: Node, guard) -> None:
        spec = self._find_type_specifier(node)
        if spec is not None:
            self._type_specifier(spec, node, guard)
        for declarator in node.children_by_field_name("declarator"):
            name = _declarator_name(declarator)
            if name is not None:
                self._add(node, name, "typedef", _text(node, self.source), guard)

    def _declaration(self, node: Node, guard) -> None:
        spec = self._find_type_specifier(node)
        if spec is not None:
            self._type_specifier(spec, node, guard)
        storage = _storage(node, self.source)
        if "extern" in storage:
            return
        type_node = node.child_by_field_name("type")
        struct_type = None
        if type_node is not None and type_node.type in ("struct_specifier", "union_specifier"):
            tag = type_node.child_by_field_name("name")
            struct_type = _text(tag, self.source) if tag is not None else None
        for declarator in node.children_by_field_name("declarator"):
            has_init = declarator.type == "init_declarator"
            target = declarator.child_by_field_name("declarator") if has_init else declarator
            if _has_function_declarator(target):
                continue  # a prototype, not a definition
            name = _declarator_name(target)
            if name is None:
                continue
            value = declarator.child_by_field_name("value") if has_init else None
            end = value.start_byte if value is not None else node.end_byte
            signature = self.source[node.start_byte : end].decode("utf-8", errors="replace")
            self._add(
                node, name, "global", signature.rstrip(" =;\n\t"), guard,
                is_static="static" in storage,
                struct_type=struct_type,
                has_initializer=value is not None and value.type == "initializer_list",
            )


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _macro_symbols(text: str, existing: list[Symbol]) -> list[Symbol]:
    """Definitions made by macros, found by line pattern rather than by the parser."""
    taken = {(s.name, s.name_line) for s in existing}
    found: list[Symbol] = []
    for match in _GLOBAL_MACRO_RE.finditer(text):
        macro = match.group("macro")
        if _DECLARATION_ONLY_RE.match(macro) or FUNCTION_MACRO_RE.match(macro):
            continue
        args = [a.strip() for a in match.group("args").split(",")]
        index = GLOBAL_MACROS.get(macro)
        if index is None:
            index = 1 if "PER_CPU" in macro else 0
        if index >= len(args) or not re.fullmatch(r"[A-Za-z_]\w*", args[index]):
            continue
        name = args[index]
        if name.isupper() or name in ("struct", "union", "enum", "static", "const"):
            continue
        line = _line_of(text, match.start())
        name_line = _line_of(text, match.start("args") + match.group("args").find(name))
        if (name, name_line) in taken:
            continue
        end_line = _line_of(text, match.end() - 1)
        found.append(
            Symbol(
                name=name, kind="global", start_line=line, end_line=end_line, name_line=name_line,
                signature=_squash(match.group(0).rstrip("=;\n ")),
                is_static=bool(match.group("static")), is_macro_generated=True,
                extra={"macro": macro},
            )
        )
    return found


def extract_symbols(text: str) -> tuple[list[Symbol], int]:
    """Return the symbols defined at file scope and the number of parse-error regions."""
    original = text.encode("utf-8", errors="replace")
    source = blank_annotations(original)
    tree = _PARSER.parse(source)
    extractor = _Extractor(source, original)
    extractor.walk(tree.root_node, None)
    symbols = extractor.symbols

    # Macro-generated functions the parser attached elsewhere (e.g. after `static`).
    known = {(s.name, s.name_line) for s in symbols}
    lines = text.split("\n")
    for match in _FUNCTION_MACRO_LINE_RE.finditer(text):
        name = match.group("name")
        line = _line_of(text, match.start())
        if (name, line) in known or any(s.name == name and s.kind == "function" for s in symbols):
            continue
        # body runs to the first line that is just "}"
        end_line = line
        for offset in range(line, len(lines)):
            if lines[offset].startswith("}"):
                end_line = offset + 1
                break
        symbols.append(
            Symbol(
                name=name, kind="function", start_line=line, end_line=end_line, name_line=line,
                signature=_squash(lines[line - 1]), is_static=bool(match.group("static")),
                is_macro_generated=True, extra={"macro": match.group("macro")},
            )
        )
    # Functions inside regions the parser could not make sense of.
    functions = {s.name for s in symbols if s.kind == "function"}
    for match in _STYLE_FUNCTION_RE.finditer(text):
        name = match.group("name")
        if name in functions or name in _C_KEYWORDS or name.isupper() or FUNCTION_MACRO_RE.match(name):
            continue
        head = match.group("head")
        line =_line_of(text, match.start())
        end_line = line
        for offset in range(_line_of(text, match.end()), len(lines)):
            if lines[offset].startswith("}"):
                end_line = offset + 1
                break
        functions.add(name)
        symbols.append(
            Symbol(
                name=name, kind="function", start_line=line, end_line=end_line,
                name_line=_line_of(text, match.start("name")), signature=_squash(head),
                is_static=head.startswith("static"), extra={"recovered": True},
            )
        )
    symbols.extend(_macro_symbols(text, symbols))
    symbols.sort(key=lambda s: (s.start_line, s.name_line, s.name))
    return symbols, extractor.error_nodes
