#!/usr/bin/env python3
from __future__ import annotations
import sys, re, os, ipaddress, argparse, unicodedata
from re import _parser as re_parser
from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Tuple, Set, Dict

def ensure_list_ext(path: str) -> str:
    return path if path.endswith(".list") else path + ".list"

def read_lines(path: str) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            yield ln

def write_text_lines(path: str, items: Iterable[str]) -> None:
    dst = ensure_list_ext(path)
    with open(dst, "w", encoding="utf-8") as f:
        for x in items:
            f.write(f"{x}\n")

def clean_stream(lines: Iterable[str]) -> Iterator[str]:
    for raw in lines:
        t = raw.rstrip("\r\n")
        i = t.find("#")
        if i != -1:
            t = t[:i]
        t = t.strip()
        if t:
            yield t

def is_hosts_prefix_token(tok: str) -> bool:
    try:
        ipaddress.ip_address(tok)
        return True
    except ValueError:
        return False

def label_count(d: str) -> int:
    return d.count(".") + 1 if d else 0

def _idn_to_ascii(t: str) -> str:
    try:
        return t.encode("idna").decode("ascii")
    except Exception:
        return t

_INVISIBLE_RE = re.compile(r"[\u200B\u200C\u200D\u2060\ufeff]", re.UNICODE)
_WS_RE = re.compile(r"\s+", re.UNICODE)
_LDH_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RANGE_RE = re.compile(r"^\s*([^-\s]+)\s*-\s*([^\s]+)\s*$")

def _strip_invisible_and_spaces(t: str) -> str:
    t = _INVISIBLE_RE.sub("", t)
    return _WS_RE.sub("", t)

def _is_valid_hostname_ascii(puny: str) -> bool:
    if not puny or len(puny) > 253:
        return False
    parts = puny.split(".")
    for lbl in parts:
        if not (1 <= len(lbl) <= 63):
            return False
        if _LDH_LABEL_RE.fullmatch(lbl) is None:
            return False
    return True

def normalize_domain_base(s: str) -> str:
    stripped = s.strip()
    if stripped.isascii() and _WS_RE.search(stripped) is None:
        base = stripped.lower().strip(".")
        return base if not base or _is_valid_hostname_ascii(base) else ""
    t = unicodedata.normalize("NFC", stripped)
    t = _strip_invisible_and_spaces(t).lower()
    t = re.sub(r"^[.]+", "", t).strip(".")
    if not t:
        return t
    puny = _idn_to_ascii(t)
    if not _is_valid_hostname_ascii(puny):
        return ""
    return puny

def strip_clean_prefixes(s: str) -> str:
    t = s.strip()
    while True:
        if t.startswith("*."):
            t = t[2:]; continue
        if t.startswith("."):
            t = t[1:]; continue
        break
    return t

def _normalize_mihomo_pattern_base(s: str) -> str:
    parts = s.strip().split(".")
    if not parts:
        return ""
    out: List[str] = []
    for lbl in parts:
        if lbl == "":
            return ""
        if lbl == "*":
            out.append("*"); continue
        t = unicodedata.normalize("NFC", lbl)
        t = _strip_invisible_and_spaces(t).lower()
        try:
            puny = t.encode("idna").decode("ascii")
        except Exception:
            return ""
        if _LDH_LABEL_RE.fullmatch(puny) is None:
            return ""
        out.append(puny)
    return ".".join(out).strip(".")

def split_leading_marker_mihomo(s: str) -> Tuple[str, str]:
    if s.startswith("+."):
        return ("suffix", _normalize_mihomo_pattern_base(s[2:]))
    if s.startswith("*.") or s.startswith(".*"):
        return ("suffix", _normalize_mihomo_pattern_base(s[2:]))
    if s.startswith("."):
        return ("suffix", _normalize_mihomo_pattern_base(s[1:]))
    return ("exact", _normalize_mihomo_pattern_base(s))

def _remove_wild_labels(base: str) -> str:
    parts = [p for p in base.split(".") if p and p != "*"]
    return ".".join(parts)

@dataclass
class _TrieNode:
    children: Dict[str, "_TrieNode"] = field(default_factory=dict)
    suffix: bool = False
    full: bool = False

def _labels_rev(base: str) -> List[str]:
    return base.split(".")[::-1] if base else []

def _trie_insert(root: _TrieNode, base: str, flag: str) -> None:
    node = root
    for lab in _labels_rev(base):
        node = node.children.setdefault(lab, _TrieNode())
    if flag == "suffix":
        node.suffix = True
    elif flag == "full":
        node.full = True

def _prune(node: _TrieNode, has_suffix_above: bool = False) -> None:
    if has_suffix_above:
        node.suffix = False
        node.full = False
        for ch in node.children.values():
            _prune(ch, True)
        return
    if node.suffix and node.full:
        node.full = False
    next_has_suffix = has_suffix_above or node.suffix
    for ch in node.children.values():
        _prune(ch, next_has_suffix)

def _trie_collect(node: _TrieNode, path_rev: List[str], out_suffix: Set[str], out_full: Set[str]) -> None:
    base = ".".join(path_rev[::-1]) if path_rev else ""
    if node.suffix and base:
        out_suffix.add(base)
    if node.full and base:
        out_full.add(base)
    for lab, ch in node.children.items():
        _trie_collect(ch, path_rev + [lab], out_suffix, out_full)

def optimize_suffix_full(entries: Iterable[Tuple[str, str]]) -> Tuple[Set[str], Set[str]]:
    root = _TrieNode()
    for t, b in entries:
        if b:
            _trie_insert(root, b, t)
    _prune(root, False)
    E: Set[str] = set()
    S: Set[str] = set()
    _trie_collect(root, [], S, E)
    return S, E

def dedup_other_rules(other_rules: Iterable[Tuple[str, str]]) -> Tuple[List[str], List[str]]:
    kw: List[str] = []; rx: List[str] = []
    seen_kw: Set[str] = set(); seen_rx: Set[str] = set()
    for kind, val in other_rules:
        if kind == "keyword":
            if val not in seen_kw:
                seen_kw.add(val); kw.append(val)
        elif kind == "regexp":
            if val not in seen_rx:
                seen_rx.add(val); rx.append(val)
    return kw, rx


def _parse_safe_regexp(pattern: str):
    if len(pattern) > 1000:
        return None
    try:
        return re_parser.parse(pattern)
    except (re.error, RecursionError):
        return None


def _regexp_required_literals(pattern: str) -> Set[str]:
    """Find substrings that every match must contain; unknown syntax proves nothing."""
    parsed = _parse_safe_regexp(pattern)
    if parsed is None:
        return set()
    if parsed.state.flags & re.IGNORECASE:
        return set()

    def collect(tokens: Iterable[Tuple[object, object]]) -> Set[str]:
        required: Set[str] = set()
        literal_run: List[str] = []

        def flush() -> None:
            if literal_run:
                required.add("".join(literal_run))
                literal_run.clear()

        for operation, value in tokens:
            if operation == re_parser.LITERAL:
                literal_run.append(chr(value))
                continue
            flush()
            if operation == re_parser.SUBPATTERN:
                _, add_flags, _, child = value
                if not add_flags & re.IGNORECASE:
                    required.update(collect(child))
            elif operation in (re_parser.MAX_REPEAT, re_parser.MIN_REPEAT):
                minimum, _, child = value
                if minimum:
                    required.update(collect(child))
            elif operation == re_parser.BRANCH:
                _, branches = value
                branch_literals = [collect(branch) for branch in branches]
                if branch_literals:
                    required.update(
                        literal
                        for literal in branch_literals[0]
                        if all(
                            any(literal in candidate for candidate in others)
                            for others in branch_literals[1:]
                        )
                    )
        flush()
        return required

    try:
        return collect(parsed.data)
    except RecursionError:
        return set()


def _regexp_fixed_suffix(pattern: str) -> str:
    """Find a literal end-anchored tail shared by every match."""
    parsed = _parse_safe_regexp(pattern)
    if parsed is None:
        return ""
    if parsed.state.flags & re.IGNORECASE:
        return ""
    tokens = parsed.data
    if not tokens or tokens[-1] != (re_parser.AT, re_parser.AT_END):
        return ""
    suffix: List[str] = []
    for operation, value in reversed(tokens[:-1]):
        if operation != re_parser.LITERAL:
            break
        suffix.append(chr(value))
    return "".join(reversed(suffix))


def _compile_safe_regexp(pattern: str) -> re.Pattern[str] | None:
    """Avoid Python backtracking on regexps that Go's RE2 can handle safely."""
    parsed = _parse_safe_regexp(pattern)
    if parsed is None:
        return None

    repeat_count = 0

    def safe(tokens: Iterable[Tuple[object, object]], repeated: bool = False) -> bool:
        nonlocal repeat_count
        for operation, value in tokens:
            if operation in (re_parser.MAX_REPEAT, re_parser.MIN_REPEAT):
                repeat_count += 1
                if repeated or repeat_count > 2 or not safe(value[2], True):
                    return False
            elif operation == re_parser.SUBPATTERN:
                if not safe(value[3], repeated):
                    return False
            elif operation == re_parser.BRANCH:
                if repeated or not all(safe(branch) for branch in value[1]):
                    return False
            elif operation not in (
                re_parser.LITERAL,
                re_parser.NOT_LITERAL,
                re_parser.IN,
                re_parser.ANY,
                re_parser.CATEGORY,
                re_parser.AT,
            ):
                return False
        return True

    try:
        is_safe = safe(parsed.data)
    except RecursionError:
        return None
    if not is_safe:
        return None
    try:
        return re.compile(pattern, re.ASCII)
    except (re.error, RecursionError):
        return None


def _regexp_context_free(tokens: Iterable[Tuple[object, object]]) -> bool:
    """A match remains valid when surrounded by more hostname characters."""
    for operation, value in tokens:
        if operation == re_parser.SUBPATTERN:
            if not _regexp_context_free(value[3]):
                return False
        elif operation == re_parser.BRANCH:
            if not all(_regexp_context_free(branch) for branch in value[1]):
                return False
        elif operation in (re_parser.MAX_REPEAT, re_parser.MIN_REPEAT):
            if not _regexp_context_free(value[2]):
                return False
        elif operation not in (
            re_parser.LITERAL,
            re_parser.NOT_LITERAL,
            re_parser.IN,
            re_parser.ANY,
            re_parser.CATEGORY,
        ):
            return False
    return True


def _regexp_simple_rule(pattern: str) -> Tuple[str, str] | None:
    """Recognize regexps equivalent to a keyword, full domain, or suffix."""
    parsed = _parse_safe_regexp(pattern)
    if parsed is None:
        return None
    if parsed.state.flags & re.IGNORECASE:
        return None

    def literals(tokens: Iterable[Tuple[object, object]]) -> str | None:
        chars: List[str] = []
        for operation, value in tokens:
            if operation != re_parser.LITERAL:
                return None
            chars.append(chr(value))
        return "".join(chars) if chars else None

    tokens = parsed.data
    plain = literals(tokens)
    if plain:
        return "keyword", plain
    try:
        context_free = _regexp_context_free(tokens)
    except RecursionError:
        context_free = False
    if context_free:
        compiled = _compile_safe_regexp(pattern)
        if compiled and compiled.search("") is not None:
            return "all", ""
        for literal in sorted(_regexp_required_literals(pattern), key=lambda value: (len(value), value)):
            if compiled and literal and literal == literal.lower() and compiled.search(literal):
                return "keyword", literal
    if len(tokens) >= 3 and tokens[0] == (re_parser.AT, re_parser.AT_BEGINNING) and tokens[-1] == (re_parser.AT, re_parser.AT_END):
        exact = literals(tokens[1:-1])
        if exact and exact == normalize_domain_base(exact):
            return "full", exact
    if len(tokens) >= 3 and tokens[0][0] == re_parser.SUBPATTERN and tokens[-1] == (re_parser.AT, re_parser.AT_END):
        _, add_flags, _, group = tokens[0][1]
        if add_flags or len(group) != 1 or group[0][0] != re_parser.BRANCH:
            return None
        _, branches = group[0][1]
        if len(branches) != 2:
            return None
        options = [list(branch) for branch in branches]
        if [(re_parser.AT, re_parser.AT_BEGINNING)] not in options or [(re_parser.LITERAL, ord("."))] not in options:
            return None
        suffix = literals(tokens[1:-1])
        if suffix and suffix == normalize_domain_base(suffix):
            return "suffix", suffix
    return None


def _regexp_finite_domains(pattern: str, limit: int = 256) -> Set[str] | None:
    """Enumerate small, end-anchored literal languages shared by Python re and RE2."""
    parsed = _parse_safe_regexp(pattern)
    if parsed is None:
        return None
    if parsed.state.flags & re.IGNORECASE:
        return None
    tokens = parsed.data
    if len(tokens) < 3 or tokens[0] != (re_parser.AT, re_parser.AT_BEGINNING) or tokens[-1] != (re_parser.AT, re_parser.AT_END):
        return None

    def combine(left: Set[str], right: Set[str]) -> Set[str] | None:
        if len(left) * len(right) > limit:
            return None
        combined = {a + b for a in left for b in right}
        return combined if len(combined) <= limit else None

    def expand(parts: Iterable[Tuple[object, object]]) -> Set[str] | None:
        values = {""}
        for operation, value in parts:
            choices: Set[str] | None = None
            if operation == re_parser.LITERAL:
                choices = {chr(value)}
            elif operation == re_parser.IN:
                choices = set()
                for kind, item in value:
                    if kind == re_parser.LITERAL:
                        choices.add(chr(item))
                    elif kind == re_parser.RANGE and item[1] - item[0] < limit:
                        choices.update(chr(code) for code in range(item[0], item[1] + 1))
                    else:
                        return None
                    if len(choices) > limit:
                        return None
            elif operation == re_parser.SUBPATTERN:
                _, add_flags, del_flags, child = value
                if add_flags or del_flags:
                    return None
                choices = expand(child)
            elif operation == re_parser.BRANCH:
                choices = set()
                for branch in value[1]:
                    branch_values = expand(branch)
                    if branch_values is None:
                        return None
                    choices.update(branch_values)
                    if len(choices) > limit:
                        return None
            elif operation in (re_parser.MAX_REPEAT, re_parser.MIN_REPEAT):
                minimum, maximum, child = value
                if minimum != maximum or maximum > 8:
                    return None
                child_values = expand(child)
                if child_values is None:
                    return None
                choices = {""}
                for _ in range(minimum):
                    choices = combine(choices, child_values)
                    if choices is None:
                        return None
            if choices is None:
                return None
            values = combine(values, choices)
            if values is None:
                return None
        return values

    try:
        domains = expand(tokens[1:-1])
    except RecursionError:
        return None
    if not domains or any(value != normalize_domain_base(value) for value in domains):
        return None
    return domains


def optimize_xray_coverage(
    suffixes: Set[str], fulls: Set[str], other_rules: Iterable[Tuple[str, str]]
) -> Tuple[Set[str], Set[str], List[Tuple[str, str]]]:
    keywords, regexps = dedup_other_rules(other_rules)
    universal_regexps = sorted(
        pattern for pattern in regexps
        if _regexp_simple_rule(pattern) == ("all", "")
    )
    if universal_regexps:
        return set(), set(), [("regexp", universal_regexps[0])]
    kept_keywords: List[str] = []
    for keyword in sorted({value.lower() for value in keywords}, key=lambda value: (len(value), value)):
        if not any(cover in keyword for cover in kept_keywords):
            kept_keywords.append(keyword)

    def suffix_covers(name: str) -> bool:
        return any(name == suffix or name.endswith("." + suffix) for suffix in suffixes)

    candidates = []
    for pattern in regexps:
        simple = _regexp_simple_rule(pattern)
        required = _regexp_required_literals(pattern)
        fixed_suffix = _regexp_fixed_suffix(pattern)
        finite_domains = _regexp_finite_domains(pattern)
        if any(keyword in literal for keyword in kept_keywords for literal in required):
            continue
        if finite_domains and all(
            suffix_covers(name) or any(keyword in name for keyword in kept_keywords)
            for name in finite_domains
        ):
            continue
        if simple and simple[0] == "full" and (simple[1] in fulls or suffix_covers(simple[1])):
            continue
        if simple and simple[0] == "suffix" and suffix_covers(simple[1]):
            continue
        if any(fixed_suffix.endswith("." + suffix) for suffix in suffixes):
            continue
        candidates.append((pattern, simple, required, fixed_suffix, finite_domains))

    def candidate_key(item):
        pattern, simple, _, _, finite_domains = item
        if finite_domains:
            priority = 3
        elif simple and simple[0] == "keyword":
            priority = 0
        elif simple and simple[0] == "suffix":
            priority = 1
        else:
            priority = 2
        return (
            priority,
            -len(finite_domains) if finite_domains else 0,
            len(simple[1]) if simple else 0,
            pattern,
        )

    candidates.sort(key=candidate_key)
    kept_regexps = []
    kept_compiled_regexps: List[re.Pattern[str]] = []
    unanchored_compiled_regexps: List[Tuple[str, re.Pattern[str]]] = []
    regex_keywords: List[str] = []
    regex_suffixes: List[str] = []
    for pattern, simple, required, fixed_suffix, finite_domains in candidates:
        if any(keyword in literal for keyword in regex_keywords for literal in required):
            continue
        if finite_domains and all(
            suffix_covers(name)
            or any(keyword in name for keyword in kept_keywords + regex_keywords)
            or any(regexp.search(name) for regexp in kept_compiled_regexps)
            for name in finite_domains
        ):
            continue
        if any(fixed_suffix.endswith("." + suffix) for suffix in regex_suffixes):
            continue
        if simple and simple[0] in ("full", "suffix") and any(
            simple[1] == suffix or simple[1].endswith("." + suffix)
            for suffix in regex_suffixes
        ):
            continue
        kept_regexps.append(pattern)
        compiled = _compile_safe_regexp(pattern)
        if compiled:
            kept_compiled_regexps.append(compiled)
            parsed = _parse_safe_regexp(pattern)
            if parsed is not None:
                try:
                    if _regexp_context_free(parsed.data):
                        unanchored_compiled_regexps.append((pattern, compiled))
                except RecursionError:
                    pass
        if simple:
            if simple[0] == "keyword":
                regex_keywords.append(simple[1])
            elif simple[0] == "suffix":
                regex_suffixes.append(simple[1])

    redundant_literal_regexps = {
        pattern for pattern in kept_regexps
        if (simple := _regexp_simple_rule(pattern)) and simple[0] == "keyword"
        and any(
            other != pattern and regexp.search(simple[1])
            for other, regexp in unanchored_compiled_regexps
        )
    }
    if redundant_literal_regexps:
        kept_regexps = [
            pattern for pattern in kept_regexps if pattern not in redundant_literal_regexps
        ]

    kept_keywords = [
        value for value in kept_keywords
        if not any(cover in value for cover in regex_keywords)
        and not any(regexp.search(value) for _, regexp in unanchored_compiled_regexps)
    ]
    suffixes = {
        value for value in suffixes
        if not any(keyword in value for keyword in kept_keywords + regex_keywords)
        and not any(regexp.search(value) for _, regexp in unanchored_compiled_regexps)
        and not any(value == suffix or value.endswith("." + suffix) for suffix in regex_suffixes)
    }
    fulls = {
        value for value in fulls
        if not any(keyword in value for keyword in kept_keywords + regex_keywords)
        and not any(regexp.search(value) for regexp in kept_compiled_regexps)
    }
    remaining = [("keyword", value) for value in kept_keywords]
    remaining.extend(("regexp", value) for value in kept_regexps)
    return suffixes, fulls, remaining

def build_xray_output(suffixes: Set[str], fulls: Set[str], other_rules: Iterable[Tuple[str, str]]) -> List[str]:
    kw_list, rx_list = dedup_other_rules(other_rules)
    items: List[Tuple[str, str]] = []
    items += [(b, "full") for b in fulls]
    items += [(b, "domain") for b in suffixes]
    items += [(v, "keyword") for v in kw_list]
    items += [(v, "regexp") for v in rx_list]
    rank = {"full": 0, "domain": 1, "keyword": 2, "regexp": 3}
    def key(t: Tuple[str, str]) -> Tuple[int, int, str]:
        val, kind = t
        return (rank.get(kind, 99), label_count(val), val)
    items.sort(key=key)
    out: List[str] = []
    for val, kind in items:
        if kind == "full":
            out.append(f"full:{val}")
        elif kind == "domain":
            out.append(f"domain:{val}")
        elif kind == "keyword":
            out.append(f"keyword:{val}")
        elif kind == "regexp":
            out.append(f"regexp:{val}")
    return out

def _collect_bases_from_tokens(tokens: Iterable[str]) -> List[str]:
    out: List[str] = []
    for tok in tokens:
        base = normalize_domain_base(strip_clean_prefixes(tok))
        if base:
            out.append(base)
    return out

def collect_clean_bases_from_clean(cleaned_lines: Iterable[str]) -> List[str]:
    return _collect_bases_from_tokens(cleaned_lines)

def collect_clean_bases_from_hosts(cleaned_lines: Iterable[str]) -> List[str]:
    out: List[str] = []
    for t in cleaned_lines:
        parts = t.split()
        if len(parts) >= 2 and is_hosts_prefix_token(parts[0]):
            out.extend(_collect_bases_from_tokens(parts[1:]))
    return out

def take_until_attr(text: str) -> str:
    parts = text.strip().split()
    keep: List[str] = []
    for tok in parts:
        if tok.startswith("@"):
            break
        keep.append(tok)
    return " ".join(keep).strip()

def parse_xray_file_recursive(path: str, visited: Set[str]) -> Tuple[List[str], List[str], List[Tuple[str, str]]]:
    abspath = os.path.abspath(path)
    if abspath in visited:
        return [], [], []
    if not os.path.exists(abspath):
        print(f"include not found: {path}", file=sys.stderr); sys.exit(2)
    visited.add(abspath)
    base_dir = os.path.dirname(abspath)
    suffix_bases: List[str] = []
    full_bases: List[str] = []
    other_rules: List[Tuple[str, str]] = []
    for line in clean_stream(read_lines(abspath)):
        if line.startswith("include:"):
            inc = take_until_attr(line[len("include:"):])
            inc_path = os.path.join(base_dir, inc)
            p2, e2, o2 = parse_xray_file_recursive(inc_path, visited)
            suffix_bases.extend(p2); full_bases.extend(e2); other_rules.extend(o2); continue
        if line.startswith("keyword:"):
            val = take_until_attr(line[len("keyword:"):])
            if val: other_rules.append(("keyword", val)); continue
        if line.startswith("regexp:"):
            val = take_until_attr(line[len("regexp:"):])
            if val: other_rules.append(("regexp", val)); continue
        if line.startswith("full:"):
            val = take_until_attr(line[len("full:"):]); base = normalize_domain_base(val)
            if base: full_bases.append(base); continue
        if line.startswith("domain:"):
            val = take_until_attr(line[len("domain:"):]); base = normalize_domain_base(val)
            if base: suffix_bases.append(base); continue
        bare = take_until_attr(line); base = normalize_domain_base(bare)
        if base: suffix_bases.append(base)
    return suffix_bases, full_bases, other_rules

def domains_from_hosts(cleaned: Iterable[str], target: str) -> List[str]:
    bases = collect_clean_bases_from_hosts(cleaned)
    entries = [("suffix", b) for b in bases] if target == "suffix" else [("full", b) for b in bases]
    S, E = optimize_suffix_full(entries)
    return build_xray_output(S, E, [])

def domains_from_clean(cleaned: Iterable[str], target: str) -> List[str]:
    bases = collect_clean_bases_from_clean(cleaned)
    entries = [("suffix", b) for b in bases] if target == "suffix" else [("full", b) for b in bases]
    S, E = optimize_suffix_full(entries)
    return build_xray_output(S, E, [])

def domains_from_mihomo(cleaned: Iterable[str]) -> List[str]:
    entries: List[Tuple[str, str]] = []
    for t in cleaned:
        kind, base = split_leading_marker_mihomo(t)
        if not base:
            continue
        if kind == "suffix":
            b2 = _remove_wild_labels(base)
            if b2:
                entries.append(("suffix", b2))
            continue
        if kind == "exact":
            if "*" in base:
                b2 = _remove_wild_labels(base)
                if b2:
                    entries.append(("suffix", b2))
            else:
                entries.append(("full", base))
    S, E = optimize_suffix_full(entries)
    return build_xray_output(S, E, [])

def domains_from_xray(path: str, optimize_for_xray: bool = False) -> List[str]:
    suffix_bases, full_bases, other_rules = parse_xray_file_recursive(path, set())
    entries: List[Tuple[str, str]] = []
    entries.extend(("suffix", b) for b in suffix_bases)
    entries.extend(("full", b) for b in full_bases)
    S, E = optimize_suffix_full(entries)
    if optimize_for_xray:
        S, E, other_rules = optimize_xray_coverage(S, E, other_rules)
    return build_xray_output(S, E, other_rules)

class _IPTrieNode:
    __slots__ = ("z", "o", "covered")
    def __init__(self):
        self.z: _IPTrieNode | None = None
        self.o: _IPTrieNode | None = None
        self.covered: bool = False

def _insert_network(root: _IPTrieNode, net: ipaddress._BaseNetwork) -> None:
    node = root
    nint = int(net.network_address)
    plen = net.prefixlen
    total = net.max_prefixlen
    for i in range(plen):
        bit = (nint >> (total - 1 - i)) & 1
        if bit == 0:
            if node.z is None:
                node.z = _IPTrieNode()
            node = node.z
        else:
            if node.o is None:
                node.o = _IPTrieNode()
            node = node.o
        if node.covered:
            return
    node.covered = True
    node.z = None
    node.o = None

def _compress_collect(node: _IPTrieNode, prefix_int: int, depth: int, acc: List[Tuple[int, int]]) -> bool:
    if node is None:
        return False
    if node.covered:
        acc.append((prefix_int, depth))
        return True
    zl = _compress_collect(node.z, prefix_int << 1, depth + 1, acc)
    ol = _compress_collect(node.o, (prefix_int << 1) | 1, depth + 1, acc)
    if zl and ol:
        acc.pop()
        acc.pop()
        acc.append((prefix_int, depth))
        node.covered = True
        node.z = None
        node.o = None
        return True
    return False

def _trie_aggregate(networks: List[ipaddress._BaseNetwork]) -> List[ipaddress._BaseNetwork]:
    v4_root = _IPTrieNode()
    v6_root = _IPTrieNode()
    for n in networks:
        if n.version == 4:
            _insert_network(v4_root, n)
        else:
            _insert_network(v6_root, n)
    out: List[ipaddress._BaseNetwork] = []
    tmp: List[Tuple[int, int]] = []

    tmp.clear()
    _compress_collect(v4_root, 0, 0, tmp)
    for pfx_int, plen in tmp:
        out.append(ipaddress.IPv4Network((pfx_int << (32 - plen), plen)))

    tmp.clear()
    _compress_collect(v6_root, 0, 0, tmp)
    for pfx_int, plen in tmp:
        out.append(ipaddress.IPv6Network((pfx_int << (128 - plen), plen)))

    out.sort(key=lambda n: (n.version, n.prefixlen, int(n.network_address)))
    return out

def _parse_ip_line_to_networks(t: str) -> List[ipaddress._BaseNetwork]:
    m = _RANGE_RE.match(t)
    if m:
        try:
            a = ipaddress.ip_address(m.group(1))
            b = ipaddress.ip_address(m.group(2))
        except ValueError:
            return []
        if a.version != b.version:
            return []
        if int(a) > int(b):
            a, b = b, a
        return list(ipaddress.summarize_address_range(a, b))
    try:
        return [ipaddress.ip_network(t, strict=False)]
    except ValueError:
        return []

def parse_ips_to_cidrs(path: str) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    seen: Set[Tuple[int, int, int]] = set()
    for raw in clean_stream(read_lines(path)):
        for n in _parse_ip_line_to_networks(raw.strip()):
            key = (n.version, int(n.network_address), n.prefixlen)
            if key in seen:
                continue
            seen.add(key)
            nets.append(n)
    if not nets:
        return []
    return _trie_aggregate(nets)

def cmd_domains(src: str, dst: str, input_type: str, target: str) -> None:
    if input_type in ("mihomo", "xray"):
        allowed = ("preserve",) if input_type == "mihomo" else ("preserve", "xray-optimized")
        if target not in allowed:
            print(f"for input-type {input_type} only --target {' or '.join(allowed)} is allowed", file=sys.stderr); sys.exit(2)
        if input_type == "mihomo":
            cleaned = list(clean_stream(read_lines(src)))
            write_text_lines(dst, domains_from_mihomo(cleaned)); return
        write_text_lines(dst, domains_from_xray(src, optimize_for_xray=target == "xray-optimized")); return
    if input_type in ("clean", "hosts"):
        if target not in ("suffix", "exact"):
            print("for input-type clean/hosts only --target suffix or --target exact are allowed", file=sys.stderr); sys.exit(2)
        cleaned = list(clean_stream(read_lines(src)))
        if input_type == "clean":
            write_text_lines(dst, domains_from_clean(cleaned, target)); return
        write_text_lines(dst, domains_from_hosts(cleaned, target)); return
    print("unknown input type", file=sys.stderr); sys.exit(2)

def cmd_ips(src: str, dst: str) -> None:
    nets = parse_ips_to_cidrs(src)
    items = [f"{n.network_address}/{n.prefixlen}" for n in nets]
    write_text_lines(dst, items)

def main() -> None:
    p = argparse.ArgumentParser(prog="tool", description="Domain/IP list optimizer and converter (XRAY output)")
    sub = p.add_subparsers(dest="mode", required=True)
    p_dom = sub.add_parser("domains", help="Process domain lists; output: XRAY (domain/full/keyword/regexp)")
    p_dom.add_argument("src", help="Input file")
    p_dom.add_argument("dst", help="Output .list path")
    p_dom.add_argument("--input-type", choices=["hosts", "clean", "mihomo", "xray"], required=True)
    p_dom.add_argument(
        "--target",
        choices=["suffix", "exact", "preserve", "xray-optimized"],
        required=True,
        help="preserve keeps cross-type overlaps for sources/Mihomo; xray-optimized removes proven overlaps",
    )
    p_dom.set_defaults(func=lambda a: cmd_domains(a.src, a.dst, a.input_type, a.target))
    p_ip = sub.add_parser("ips", help="Process IP/CIDR lists; output: CIDR")
    p_ip.add_argument("src", help="Input file")
    p_ip.add_argument("dst", help="Output .list path")
    p_ip.set_defaults(func=lambda a: cmd_ips(a.src, a.dst))
    args = p.parse_args()
    if args.mode == "ips":
        cmd_ips(args.src, args.dst)
    else:
        args.func(args)

if __name__ == "__main__":
    main()
