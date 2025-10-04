#!/usr/bin/env python3
from __future__ import annotations
import argparse, os, sys, re, unicodedata
from typing import List, Tuple, Set, Dict, Iterable

def read_lines(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            yield ln

def clean_stream(lines: Iterable[str]):
    for raw in lines:
        t = raw.rstrip("\r\n")
        i = t.find("#")
        if i != -1:
            t = t[:i]
        t = t.strip()
        if t:
            yield t

_INVISIBLE_RE = re.compile(r"[\u200B\u200C\u200D\u2060\ufeff]", re.UNICODE)
_WS_RE = re.compile(r"\s+", re.UNICODE)
_LDH_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

def _strip_invisible_and_spaces(t: str) -> str:
    t = _INVISIBLE_RE.sub("", t)
    return _WS_RE.sub("", t)

def _idn_to_ascii(t: str) -> str:
    try:
        return t.encode("idna").decode("ascii")
    except Exception:
        return t

def _is_valid_hostname_ascii(puny: str) -> bool:
    if not puny or len(puny) > 253:
        return False
    for lbl in puny.split("."):
        if not (1 <= len(lbl) <= 63):
            return False
        if _LDH_LABEL_RE.fullmatch(lbl) is None:
            return False
    return True

def normalize_domain_base(s: str) -> str:
    t = unicodedata.normalize("NFC", s.strip())
    t = _strip_invisible_and_spaces(t).lower()
    t = re.sub(r"^[.]+", "", t).strip(".")
    if not t:
        return t
    puny = _idn_to_ascii(t)
    return puny if _is_valid_hostname_ascii(puny) else ""

def take_until_attr(text: str) -> str:
    parts = text.strip().split()
    keep: List[str] = []
    for tok in parts:
        if tok.startswith("@"):
            break
        keep.append(tok)
    return " ".join(keep).strip()

def parse_xray_file_recursive(path: str, visited: Set[str]) -> Tuple[Set[str], Set[str]]:
    abspath = os.path.abspath(path)
    if abspath in visited:
        return set(), set()
    if not os.path.exists(abspath):
        print(f"include not found: {path}", file=sys.stderr)
        sys.exit(2)
    visited.add(abspath)
    base_dir = os.path.dirname(abspath)
    suffix_bases: Set[str] = set()
    full_bases: Set[str] = set()
    for line in clean_stream(read_lines(abspath)):
        if line.startswith("include:"):
            inc = take_until_attr(line[len("include:"):])
            s2, f2 = parse_xray_file_recursive(os.path.join(base_dir, inc), visited)
            suffix_bases |= s2
            full_bases |= f2
            continue
        if line.startswith("keyword:") or line.startswith("regexp:"):
            continue
        if line.startswith("full:"):
            val = take_until_attr(line[len("full:"):])
            base = normalize_domain_base(val)
            if base:
                full_bases.add(base)
            continue
        if line.startswith("domain:"):
            val = take_until_attr(line[len("domain:"):])
            base = normalize_domain_base(val)
            if base:
                suffix_bases.add(base)
            continue
        bare = take_until_attr(line)
        base = normalize_domain_base(bare)
        if base:
            suffix_bases.add(base)
    return suffix_bases, full_bases

class _TrieNode:
    def __init__(self):
        self.children: Dict[str, "_TrieNode"] = {}
        self.suffix: bool = False
        self.full: bool = False

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
    S: Set[str] = set()
    E: Set[str] = set()
    _trie_collect(root, [], S, E)
    return S, E

def is_under(a: str, b: str) -> bool:
    if a == b:
        return True
    return a.endswith("." + b)

def intersect_pair(A_suffix: Set[str], A_full: Set[str],
                   B_suffix: Set[str], B_full: Set[str]) -> Tuple[Set[str], Set[str]]:
    out_suf: Set[str] = set()
    out_full: Set[str] = set()

    As, Bs = (A_suffix, B_suffix) if len(A_suffix) <= len(B_suffix) else (B_suffix, A_suffix)
    for sr in As:
        for sc in Bs:
            if is_under(sr, sc):
                out_suf.add(sr)
            elif is_under(sc, sr):
                out_suf.add(sc)

    for fr in A_full:
        if fr in B_full or any(is_under(fr, sc) for sc in B_suffix):
            out_full.add(fr)

    for fc in B_full:
        if fc in A_full or any(is_under(fc, sr) for sr in A_suffix):
            out_full.add(fc)

    return optimize_suffix_full([("suffix", s) for s in out_suf] + [("full", e) for e in out_full])

def intersect_many(groups: List[Tuple[Set[str], Set[str]]]) -> Tuple[Set[str], Set[str]]:
    if not groups:
        return set(), set()
    S, E = groups[0]
    for s2, e2 in groups[1:]:
        if not S and not E:
            break
        S, E = intersect_pair(S, E, s2, e2)
    return S, E

def render_xray(suffixes: Set[str], fulls: Set[str]) -> List[str]:
    items = [("full", b) for b in fulls] + [("domain", b) for b in suffixes]
    rank = {"full": 0, "domain": 1}
    def label_count(d: str) -> int:
        return d.count(".") + 1 if d else 0
    items.sort(key=lambda t: (rank[t[0]], label_count(t[1]), t[1]))
    out: List[str] = []
    for k, b in items:
        if k == "full":
            out.append(f"full:{b}")
        else:
            out.append(b)
    return out

def read_group(arg: str) -> Tuple[Set[str], Set[str]]:
    suffix: Set[str] = set()
    full: Set[str] = set()
    visited: Set[str] = set()
    for p in [s.strip() for s in arg.split(",") if s.strip()]:
        s, f = parse_xray_file_recursive(p, visited)
        suffix |= s
        full |= f
    S, E = optimize_suffix_full([("suffix", s) for s in suffix] + [("full", e) for e in full])
    return S, E

def main():
    ap = argparse.ArgumentParser(description="Domain set ops (XRAY). Intersection across groups.")
    ap.add_argument("--mode", choices=["intersect"], required=True)
    ap.add_argument("--set", action="append", default=[], help="группа файлов через запятую (union внутри), несколько --set для пересечения между группами")
    ap.add_argument("--out", required=True, help="output .list (XRAY)")
    args = ap.parse_args()

    if args.mode != "intersect":
        print("unsupported mode", file=sys.stderr)
        sys.exit(2)
    if len(args.set) < 2:
        print("intersect requires at least two --set groups", file=sys.stderr)
        sys.exit(2)

    groups = [read_group(s) for s in args.set]
    S, E = intersect_many(groups)
    dst = args.out if args.out.endswith(".list") else args.out + ".list"
    with open(dst, "w", encoding="utf-8") as f:
        for line in render_xray(S, E):
            f.write(line + "\n")

if __name__ == "__main__":
    main()
