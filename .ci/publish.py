#!/usr/bin/env python3
"""Publish at most three linear snapshots, guarded by the caller's original lease."""
import argparse
import os
import re
import subprocess
import sys


BRANCHES = {"sources", "server", "xray-rulesets", "mihomo-rulesets", "sing-box-rulesets"}


def git(*args, data=None):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    return subprocess.run(["git", *args], input=data, stdout=subprocess.PIPE,
                          env=env, check=True).stdout


def object_id(value, kind):
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        raise ValueError(f"expected full {kind} object ID")
    if git("cat-file", "-t", value).strip().decode() != kind:
        raise ValueError(f"object is not a {kind}: {value}")
    return value


def snapshot(oid):
    raw = git("cat-file", "commit", oid)
    headers, message = raw.split(b"\n\n", 1)
    lines = headers.split(b"\n")
    parents = [line[7:].decode() for line in lines if line.startswith(b"parent ")]
    if len(parents) > 1:
        raise ValueError("merge snapshot history is not supported")
    tree = next(line[5:].decode() for line in lines if line.startswith(b"tree "))
    # Signatures cannot survive parent rewrites. Preserve snapshot identity metadata
    # and encoding byte-for-byte, not through locale-dependent commit formatting.
    retained = [line for line in lines if line.startswith(
        (b"tree ", b"author ", b"committer ", b"encoding "))]
    return tree, parents, retained, message


def publish(args):
    if args.branch not in BRANCHES:
        raise ValueError(f"branch not allowed: {args.branch}")
    tree = object_id(args.tree, "tree")
    current = object_id(args.expected, "commit") if args.expected else ""
    snapshots = []
    changed = True
    if current:
        first = snapshot(current)
        changed = first[0] != tree
        limit = 2 if changed else 3
        while current and len(snapshots) < limit:
            entry = first if not snapshots else snapshot(current)
            snapshots.append((current, entry))
            current = entry[1][0] if entry[1] else ""

    parent = args.expected
    if current:
        # Raw parent headers above detect history hidden by a shallow boundary.
        # Rebuild only retained commits, oldest first; no ancestors/blobs required.
        parent = ""
        for _, (_, _, headers, message) in reversed(snapshots):
            lines = headers[:1]
            if parent:
                lines.append(f"parent {parent}".encode())
            lines.extend(headers[1:])
            raw = b"\n".join(lines) + b"\n\n" + message
            parent = git("hash-object", "-t", "commit", "-w", "--stdin", data=raw).strip().decode()
    elif not changed:
        print("Snapshot unchanged; history already bounded")
        return

    if changed:
        command = ["commit-tree", tree]
        if parent:
            command.extend(["-p", parent])
        parent = git(*command, data=args.message.encode() + b"\n").strip().decode()

    # Git may lazy-fetch retained blobs to pack disconnected rewritten history;
    # the bounded unchanged path above never invokes push or reads any blob.
    ref = f"refs/heads/{args.branch}"
    git("push", f"--force-with-lease={ref}:{args.expected}", "origin", f"{parent}:{ref}")
    print(f"Published {parent} to {ref}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--message", required=True)
    args = parser.parse_args()
    try:
        publish(args)
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"Publication failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
