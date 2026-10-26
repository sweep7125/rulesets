#!/usr/bin/env python3
"""Build INCY's Android package list from two plain Mihomo PROCESS-NAME lists."""
import argparse
from pathlib import Path
import re
import sys

PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+')


def packages(text, *, android_only=False):
    result = set()
    payload = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if not payload and line == 'payload:':
            payload = True
            continue
        if not payload or not line.startswith('- PROCESS-NAME,'):
            raise ValueError(f'line {number}: expected payload with PROCESS-NAME entries')
        name = line.removeprefix('- PROCESS-NAME,').strip()
        if not name or ',' in name:
            raise ValueError(f'line {number}: malformed PROCESS-NAME entry')
        valid = not name.lower().endswith('.exe') and PACKAGE.fullmatch(name)
        if valid:
            result.add(name)
        elif not android_only:
            raise ValueError(f'line {number}: invalid Android package: {name!r}')
    if not result:
        raise ValueError('source contains no Android packages')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('torrent', type=Path)
    parser.add_argument('ru', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        torrent = packages(args.torrent.read_text(encoding='utf-8-sig'), android_only=True)
        ru = packages(args.ru.read_text(encoding='utf-8-sig'))
        combined = sorted(torrent | ru)
        args.output.write_text('\n'.join(combined) + '\n', encoding='utf-8')
    except (OSError, ValueError) as error:
        print(f'Application list build failed: {error}', file=sys.stderr)
        return 1
    print(f'Torrent: {len(torrent)}; RU: {len(ru)}; combined: {len(combined)} unique packages')
    return 0


if __name__ == '__main__':
    sys.exit(main())
