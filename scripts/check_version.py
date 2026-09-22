#!/usr/bin/env python3
"""Validate release metadata against VERSION."""
import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:[+][0-9A-Za-z.-]+)?$")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected")
    args = parser.parse_args()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        raise SystemExit(f"Invalid semantic VERSION: {version!r}")
    expected = args.expected.removeprefix("v") if args.expected else version
    app_source = (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
    match = re.search(r'version="([^"]+)"', app_source)
    values = {
        "VERSION": version,
        "backend/pyproject.toml": tomllib.loads((ROOT / "backend/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"],
        "frontend/package.json": json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))["version"],
        "backend/app/main.py": match.group(1) if match else "<missing>",
    }
    bad = {name: value for name, value in values.items() if value != expected}
    for name, value in bad.items():
        print(f"{name}: expected {expected}, found {value}", file=sys.stderr)
    if bad:
        return 1
    print(f"Version metadata is consistent: {version}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
