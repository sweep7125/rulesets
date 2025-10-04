#!/usr/bin/env python3
from __future__ import annotations
import sys, os, re, argparse, unicodedata
from typing import Iterable, Iterator, List, Tuple, Set

def read_lines(path: str) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            yield ln

def clean_stream(lines: Iterable[str]) -> Iterator[str]:
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
    parts = puny.split(".")
    for lbl in parts:
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
    if not _is_valid_hostname_ascii(puny):
        return ""
    return puny

def label_count(d: str) -> int:
    return d.count(".") + 1 if d else 0

def take_until_attr(text: str) -> str:
    parts = text.strip().split()
    keep: List[str] = []
    for tok in parts:
        if tok.startswith("@"):
            break
        keep.append(tok)
    return " ".join(keep).strip()

def resolve_file_or_list(path: str) -> str:
    p = os.path.abspath(path)
    if os.path.exists(p):
        return p
    p_list = p + ".list"
    if os.path.exists(p_list):
        return p_list
    print(f"file not found: {path}", file=sys.stderr); sys.exit(2)

def parse_xray_file_recursive(path: str, visited: Set[str]) -> Tuple[Set[str], Set[str]]:
    abspath = os.path.abspath(path)
    if abspath in visited:
        return set(), set()
    if not os.path.exists(abspath):
        print(f"include not found: {path}", file=sys.stderr); sys.exit(2)
    visited.add(abspath)
    base_dir = os.path.dirname(abspath)
    suf: Set[str] = set()
    ful: Set[str] = set()
    for line in clean_stream(read_lines(abspath)):
        if line.startswith("include:"):
            inc = take_until_attr(line[len("include:"):])
            inc_path = os.path.join(base_dir, inc)
            s2, f2 = parse_xray_file_recursive(inc_path, visited)
            suf |= s2; ful |= f2; continue
        if line.startswith("keyword:") or line.startswith("regexp:"):
            continue
        if line.startswith("full:"):
            val = take_until_attr(line[len("full:"):])
            base = normalize_domain_base(val)
            if base:
                ful.add(base)
            continue
        if line.startswith("domain:"):
            val = take_until_attr(line[len("domain:"):])
            base = normalize_domain_base(val)
            if base:
                suf.add(base)
            continue
        bare = take_until_attr(line)
        base = normalize_domain_base(bare)
        if base:
            suf.add(base)
    return suf, ful

def load_union_from_group(group: List[str]) -> Tuple[Set[str], Set[str]]:
    suf: Set[str] = set()
    ful: Set[str] = set()
    for p in group:
        p_res = resolve_file_or_list(p)
        s, f = parse_xray_file_recursive(p_res, set())
        suf |= s; ful |= f
    return suf, ful

def iter_suffix_chain(name: str):
    cur = name
    yield cur
    while True:
        i = cur.find(".")
        if i == -1:
            return
        cur = cur[i+1:]
        yield cur

def group_covers_full(group_suf: Set[str], group_ful: Set[str], fqdn: str) -> bool:
    if fqdn in group_ful:
        return True
    for tail in iter_suffix_chain(fqdn):
        if tail in group_suf:
            return True
    return False

def group_covers_suffix(group_suf: Set[str], suffix: str) -> bool:
    for tail in iter_suffix_chain(suffix):
        if tail in group_suf:
            return True
    return False

def intersect_groups(sets: List[Tuple[Set[str], Set[str]]]) -> Tuple[Set[str], Set[str]]:
    if not sets:
        return set(), set()
    all_suf: Set[str] = set().union(*(s for s, _ in sets))
    all_ful: Set[str] = set().union(*(f for _, f in sets))
    out_suf: Set[str] = set()
    out_ful: Set[str] = set()
    for f in all_ful:
        ok = True
        for sset, fset in sets:
            if not group_covers_full(sset, fset, f):
                ok = False; break
        if ok:
            out_ful.add(f)
    for s in all_suf:
        ok = True
        for sset, _ in sets:
            if not group_covers_suffix(sset, s):
                ok = False; break
        if ok:
            out_suf.add(s)
    return out_suf, out_ful

def diff_simple(A: Tuple[Set[str], Set[str]], B: Tuple[Set[str], Set[str]]) -> Tuple[Set[str], Set[str]]:
    A_suf, A_ful = A
    B_suf, B_ful = B
    keep_suf: Set[str] = set()
    keep_ful: Set[str] = set()
    for f in A_ful:
        if not group_covers_full(B_suf, B_ful, f):
            keep_ful.add(f)
    for s in A_suf:
        if not group_covers_suffix(B_suf, s):
            keep_suf.add(s)
    return keep_suf, keep_ful

def emit_xray_lines(suf: Set[str], ful: Set[str]) -> List[str]:
    items: List[Tuple[int, int, str]] = []
    for f in ful:
        items.append((0, label_count(f), f"full:{f}"))
    for s in suf:
        items.append((1, label_count(s), s))
    items.sort(key=lambda t: (t[0], t[1], t[2]))
    return [x for _, _, x in items]

def parse_sets_args(raw_sets: List[str]) -> List[List[str]]:
    groups: List[List[str]] = []
    for arg in raw_sets:
        parts = [p.strip() for p in arg.split(",") if p.strip()]
        if parts:
            groups.append(parts)
    return groups

def main() -> None:
    ap = argparse.ArgumentParser(prog="domainset_ops", description="XRAY domain set operations")
    ap.add_argument("--mode", choices=["intersect", "diff-simple"], required=True)
    ap.add_argument("--set", dest="sets", action="append", required=True, help="comma-separated list of XRAY files per group (.list or without)")
    ap.add_argument("--out", required=True, help="output file path")
    a = ap.parse_args()

    groups = parse_sets_args(a.sets)
    if a.mode == "intersect":
        if len(groups) < 2:
            print("intersect requires at least two --set groups", file=sys.stderr); sys.exit(2)
        loaded = [load_union_from_group(g) for g in groups]
        suf, ful = intersect_groups(loaded)
        lines = emit_xray_lines(suf, ful)
    else:
        if len(groups) < 2:
            print("diff-simple requires at least two --set groups (A then B...)", file=sys.stderr); sys.exit(2)
        A = load_union_from_group(groups[0])
        B_groups = [load_union_from_group(g) for g in groups[1:]]
        if len(B_groups) == 1:
            B = B_groups[0]
        else:
            B = (set().union(*(s for s, _ in B_groups)), set().union(*(f for _, f in B_groups)))
        suf, ful = diff_simple(A, B)
        lines = emit_xray_lines(suf, ful)

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")

if __name__ == "__main__":
    main()
