#!/usr/bin/env python3
"""Audit the complete Git index for accidental private content, not bypass security."""
import re
from pathlib import Path
import subprocess
import sys

DENY_PATH = re.compile(r"(?:^|/)(?:internal-docs|internal-tools|\.scratch|\.ia-format-survey|target|research|reports)(?:/|$)", re.I)
DENY_TEXT = re.compile(rb"/(?:home|Users|mnt|media)/|(?:S[LC][A-Z]{2}|UL[A-Z]{2}|UC[A-Z]{2}|NP[A-Z]{2}|P[ACB]PX|DNAT)[ _-]?\d{3}[.]?\d{2}|\bsc[e][- _]?kit\b|\b(?:psxkit|pspkit|ps2kit)[-_]|\b(?:sce-core|sce-layout|sce-runtime|sce-detect|sce-corpus)\b|-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----|\b(?:sk-proj-|ghp_)[A-Za-z0-9]+", re.I)

def main():
    root = Path(__file__).resolve().parents[1]
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
    failures = []
    for raw in filter(None, paths):
        path = raw.decode("utf-8", "surrogateescape")
        if DENY_PATH.search(path):
            failures.append(f"private/generated path: {path}")
            continue
        blob = subprocess.check_output(["git", "show", ":" + path], cwd=root)
        # The gate must not flag its own literal rules.
        if path == "tools/check-public.py":
            continue
        if DENY_TEXT.search(blob):
            failures.append(f"private identifier, path or credential marker: {path}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Public index boundary: passed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
