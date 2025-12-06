from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, List, Optional


def _normalize_tokens(tokens: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for token in tokens:
        cleaned = token.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            seen.add(cleaned)
            ordered.append(cleaned)
    return ordered


def parse_dep_file(path: Path) -> List[str]:
    """Parse an iverilog-generated dependency file into a list of paths."""
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="ignore")
    raw = raw.replace("\\\n", " ")
    parts = raw.split(":", 1)
    if len(parts) == 2:
        _, rhs = parts
    else:
        rhs = parts[0]
    tokens = rhs.replace("\\", " ").split()
    return _normalize_tokens(tokens)


def build_iverilog_entry(
    *,
    source: str,
    mode: str,
    status: str,
    command: str,
    log_path: Path,
    dep_path: Optional[Path],
    output_artifact: Optional[str],
) -> dict:
    entry = {
        "source": source,
        "mode": mode,
        "status": status,
        "command": command,
        "log_path": str(log_path),
        "log_size_bytes": log_path.stat().st_size if log_path.exists() else 0,
        "dependencies": parse_dep_file(dep_path) if dep_path else [],
    }
    if output_artifact:
        entry["output_artifact"] = output_artifact
    return entry


def build_yosys_entry(
    *,
    source: str,
    status: str,
    command: str,
    log_path: Path,
    output_artifact: Optional[str],
) -> dict:
    entry = {
        "source": source,
        "status": status,
        "command": command,
        "log_path": str(log_path),
        "log_size_bytes": log_path.stat().st_size if log_path.exists() else 0,
    }
    if output_artifact:
        entry["output_artifact"] = output_artifact
    return entry


def append_jsonl_entry(jsonl_path: Path, entry: dict) -> None:
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry))
        handle.write("\n")


def jsonl_to_json(input_path: Path, output_path: Path) -> None:
    data = []
    if input_path.exists():
        with input_path.open("r", encoding="utf-8") as handle:
            for idx, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    print(f"Warning: skipping invalid JSON at line {idx}: {exc}", file=sys.stderr)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def extract_yosys_stat_json(log_path: Path) -> dict:
    text = log_path.read_text(encoding="utf-8")
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Unable to locate JSON content in Yosys stat log")
    payload = text[start : end + 1]
    return json.loads(payload)


def write_yosys_summary(log_path: Path, output_path: Path, *, missing_ok: bool = False) -> bool:
    if not log_path.exists():
        if missing_ok:
            return False
        raise FileNotFoundError(log_path)
    data = extract_yosys_stat_json(log_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    return True


def aggregate_yosys_stats(stat_paths: Iterable[Path]) -> list[dict]:
    aggregated: list[dict] = []
    for path in stat_paths:
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        source_name = path.stem
        if source_name.endswith(".stat"):
            source_name = source_name[: -len(".stat")]
        aggregated.append({
            "source": source_name,
            "stat": data,
        })
    return aggregated


def write_aggregate_stats(stat_paths: Iterable[Path], output_path: Path) -> None:
    entries = aggregate_yosys_stats(stat_paths)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(entries, handle, indent=2)


def _cmd_iverilog_entry(args: argparse.Namespace) -> int:
    entry = build_iverilog_entry(
        source=args.source,
        mode=args.mode,
        status=args.status,
        command=args.command,
        log_path=Path(args.log_path),
        dep_path=Path(args.dep_path) if args.dep_path else None,
        output_artifact=args.output_artifact,
    )
    append_jsonl_entry(Path(args.jsonl), entry)
    return 0


def _cmd_yosys_entry(args: argparse.Namespace) -> int:
    entry = build_yosys_entry(
        source=args.source,
        status=args.status,
        command=args.command,
        log_path=Path(args.log_path),
        output_artifact=args.output_artifact,
    )
    append_jsonl_entry(Path(args.jsonl), entry)
    return 0


def _cmd_jsonl_to_json(args: argparse.Namespace) -> int:
    jsonl_to_json(Path(args.input), Path(args.output))
    return 0


def _cmd_yosys_summary(args: argparse.Namespace) -> int:
    try:
        wrote = write_yosys_summary(
            Path(args.log),
            Path(args.output),
            missing_ok=args.missing_ok,
        )
    except (ValueError, FileNotFoundError) as exc:
        if args.missing_ok:
            print(f"Warning: {exc}", file=sys.stderr)
            return 0
        raise
    if not wrote and args.missing_ok:
        print("Warning: Yosys stat log not found; summary not written.", file=sys.stderr)
    return 0


def _cmd_aggregate_yosys_stats(args: argparse.Namespace) -> int:
    write_aggregate_stats((Path(p) for p in args.inputs), Path(args.output))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Utilities for CI report generation.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    iverilog = subparsers.add_parser("iverilog-entry", help="Append an iverilog entry to a JSONL file.")
    iverilog.add_argument("--jsonl", required=True)
    iverilog.add_argument("--source", required=True)
    iverilog.add_argument("--mode", required=True)
    iverilog.add_argument("--status", required=True)
    iverilog.add_argument("--command", required=True)
    iverilog.add_argument("--log-path", required=True)
    iverilog.add_argument("--dep-path")
    iverilog.add_argument("--output-artifact")
    iverilog.set_defaults(func=_cmd_iverilog_entry)

    yosys_entry = subparsers.add_parser("yosys-entry", help="Append a yosys entry to a JSONL file.")
    yosys_entry.add_argument("--jsonl", required=True)
    yosys_entry.add_argument("--source", required=True)
    yosys_entry.add_argument("--status", required=True)
    yosys_entry.add_argument("--command", required=True)
    yosys_entry.add_argument("--log-path", required=True)
    yosys_entry.add_argument("--output-artifact")
    yosys_entry.set_defaults(func=_cmd_yosys_entry)

    jsonl = subparsers.add_parser("jsonl-to-json", help="Convert a JSONL file to JSON array.")
    jsonl.add_argument("--input", required=True)
    jsonl.add_argument("--output", required=True)
    jsonl.set_defaults(func=_cmd_jsonl_to_json)

    summary = subparsers.add_parser("yosys-summary", help="Generate summary JSON from Yosys stat log.")
    summary.add_argument("--log", required=True)
    summary.add_argument("--output", required=True)
    summary.add_argument("--missing-ok", action="store_true")
    summary.set_defaults(func=_cmd_yosys_summary)

    aggregate = subparsers.add_parser("aggregate-yosys-stats", help="Aggregate per-file stat JSON outputs.")
    aggregate.add_argument("--inputs", nargs="+", required=True)
    aggregate.add_argument("--output", required=True)
    aggregate.set_defaults(func=_cmd_aggregate_yosys_stats)

    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
