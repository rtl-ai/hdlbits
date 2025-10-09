#!/usr/bin/env python3
"""
Utility to generate filelist manifests for HDL tool flows.

By default, this script scans the `v/` directory relative to the repository
root, collects every Verilog source file, and writes the relative paths into
`listfile/rtl.f`. The output is deterministic (alphabetically sorted) to keep
CI results stable.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate HDL file list manifests suitable for EDA tools."
    )
    parser.add_argument(
        "--source-root",
        default="v",
        help="Directory (relative to repo root) to scan for HDL sources (default: v).",
    )
    parser.add_argument(
        "--output-dir",
        default="listfile",
        help="Directory (relative to repo root) where list files are written (default: listfile).",
    )
    parser.add_argument(
        "--pattern",
        default="*.v",
        help="Glob pattern to match HDL sources within the source root (default: *.v).",
    )
    parser.add_argument(
        "--output-name",
        default="rtl.f",
        help="Filename for the generated list file (default: rtl.f).",
    )
    parser.add_argument(
        "--repo-root",
        default="..",
        help="Repository root relative to the script location (default: ..).",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    script_dir = Path(__file__).resolve().parent
    repo_root = (script_dir / args.repo_root).resolve()

    source_root = (repo_root / args.source_root).resolve()
    if not source_root.exists():
        raise SystemExit(f"Source root not found: {source_root}")

    output_dir = (repo_root / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / args.output_name

    sources = sorted(source_root.rglob(args.pattern))
    # Ensure we only write files that truly match the glob.
    sources = [path for path in sources if path.is_file()]

    with output_path.open("w", encoding="utf-8") as manifest:
        for path in sources:
            manifest.write(f"{path.relative_to(repo_root)}\n")

    print(f"Wrote {len(sources)} entries to {output_path.relative_to(repo_root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
