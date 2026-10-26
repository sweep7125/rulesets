#!/usr/bin/env python3
"""Prepare one flattened sources list as sing-box source JSON."""
import argparse
import ipaddress
import json
import re
from pathlib import Path

HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")
FIELDS = {"full": "domain", "domain": "domain_suffix", "keyword": "domain_keyword", "regexp": "domain_regex"}


def prepare(kind, source, keep_ipv6=False):
    rules = {}
    with source.open(encoding="utf-8") as lines:
        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if kind == "geoip":
                network = ipaddress.ip_network(line, strict=False)
                if network.version == 6 and not keep_ipv6:
                    continue
                field, value = "ip_cidr", str(network)
            else:
                typ, sep, value = line.partition(":")
                if not sep:
                    typ, value = "domain", line
                if typ not in FIELDS or not value:
                    raise ValueError(f"{source}:{lineno}: unsupported or empty domain rule: {line!r}")
                field = FIELDS[typ]
                if typ in ("domain", "full"):
                    value = value.lower()
                    if not HOST.fullmatch(value) or any(
                        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                        for label in value.split(".")
                    ):
                        raise ValueError(f"{source}:{lineno}: invalid domain: {value!r}")
            rules.setdefault(field, []).append(value)
    return {"version": 3, "rules": [rules] if rules else []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("geosite", "geoip"))
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--keep-ipv6", action="store_true")
    args = parser.parse_args()
    if args.keep_ipv6 and args.kind != "geoip":
        parser.error("--keep-ipv6 is only valid for geoip")
    try:
        document = prepare(args.kind, args.source, args.keep_ipv6)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")
    with args.output.open("w", encoding="utf-8") as output:
        json.dump(document, output, ensure_ascii=False, separators=(",", ":"))
        output.write("\n")


if __name__ == "__main__":
    main()
