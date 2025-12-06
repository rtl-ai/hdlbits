from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
from collections import Counter
from urllib import error, parse, request


WARNING_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\bwarning\b", re.IGNORECASE),
)
ERROR_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\berror\b", re.IGNORECASE),
    re.compile(r"\bfatal\b", re.IGNORECASE),
)


def _make_metric(name: str, value: int, stage: str, *, unit: str = "count", labels: dict | None = None) -> dict:
    metric = {
        "name": name,
        "value": int(value),
        "unit": unit,
        "labels": {"stage": stage},
    }
    if labels:
        metric["labels"].update(labels)
    return metric


def _count_log_messages(log_path: Path) -> tuple[int, int, bool]:
    """Return (warnings, errors, missing) for a log file."""
    warnings = 0
    errors = 0
    missing = False
    try:
        text = log_path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        missing = True
        text = ""
    for line in text.splitlines():
        if any(pattern.search(line) for pattern in WARNING_PATTERNS):
            warnings += 1
        if any(pattern.search(line) for pattern in ERROR_PATTERNS):
            errors += 1
    return warnings, errors, missing


def _load_report_entries(report_path: Path) -> List[dict]:
    if not report_path.exists():
        print(f"Warning: report not found: {report_path}", file=sys.stderr)
        return []
    try:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        print(f"Warning: unable to parse report {report_path}: {exc}", file=sys.stderr)
        return []
    if not isinstance(raw, list):
        print(f"Warning: report {report_path} is not a list; ignoring", file=sys.stderr)
        return []
    return raw


def _load_json_lines_or_list(report_path: Path) -> List[dict]:
    """Load JSON array or NDJSON list; returns empty list when missing or invalid."""
    if not report_path.exists():
        print(f"Warning: report not found: {report_path}", file=sys.stderr)
        return []
    text = report_path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass
    entries: List[dict] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            parsed_line = json.loads(line)
            if isinstance(parsed_line, dict):
                entries.append(parsed_line)
        except json.JSONDecodeError:
            print(f"Warning: skipping invalid JSON at line {idx} in {report_path}", file=sys.stderr)
    return entries


def _write_metrics(metrics: Iterable[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {"metrics": list(metrics)}
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _load_metrics_payload(path: Path) -> List[dict]:
    if not path.exists():
        print(f"Warning: metrics file not found: {path}", file=sys.stderr)
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        print(f"Warning: unable to parse metrics file {path}: {exc}", file=sys.stderr)
        return []
    metrics = payload.get("metrics", [])
    if not isinstance(metrics, list):
        print(f"Warning: metrics file {path} missing 'metrics' list; ignoring", file=sys.stderr)
        return []
    return metrics


def _format_label_str(labels: dict) -> str:
    extra = {k: v for k, v in labels.items() if k not in {"stage", "tool"}}
    if not extra:
        return "-"
    return ", ".join(f"{k}={v}" for k, v in sorted(extra.items()))


def _resolve_api_auth() -> tuple[str | None, str, str]:
    """Return (token, header, source) preferring MR_COMMENT_TOKEN then CI_JOB_TOKEN."""
    pat_token = os.environ.get("MR_COMMENT_TOKEN")
    job_token = os.environ.get("CI_JOB_TOKEN")
    if pat_token:
        return pat_token, "PRIVATE-TOKEN", "pat"
    if job_token:
        return job_token, "JOB-TOKEN", "job"
    return None, "", ""


def _encode_project(project_id: str) -> str:
    """Quote project id (numeric or path) for GitLab API URLs."""
    return parse.quote(str(project_id), safe="")


def _fetch_stage_links(project_id: str, pipeline_id: str, api: str, token: str, header: str) -> Dict[str, str]:  # pragma: no cover - network
    """Return a map of stage -> job web URL for the pipeline."""
    encoded_project = _encode_project(project_id)
    url = f"{api}/projects/{encoded_project}/pipelines/{pipeline_id}/jobs?per_page=100"
    req = request.Request(
        url,
        method="GET",
        headers={
            header: token,
            "Accept": "application/json",
        },
    )
    stage_links: Dict[str, str] = {}
    try:
        with request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, list):
                    for job in data:
                        stage = job.get("stage")
                        web_url = job.get("web_url")
                        if stage and web_url and stage not in stage_links:
                            stage_links[stage] = web_url
            else:
                print(f"Warning: pipeline jobs lookup returned status {resp.status}", file=sys.stderr)
    except error.HTTPError as exc:
        print(f"Warning: failed to list pipeline jobs: {exc}", file=sys.stderr)
    except error.URLError as exc:
        print(f"Warning: unable to reach GitLab API for pipeline jobs: {exc}", file=sys.stderr)
    return stage_links


def _format_markdown_summary(metrics: List[dict], stage_links: Dict[str, str] | None = None) -> str:
    if not metrics:
        return "# CI Metrics Summary\n\n_No metrics available._\n"

    def sort_key(entry: dict) -> tuple:
        labels = entry.get("labels", {}) or {}
        return (
            labels.get("stage", ""),
            labels.get("tool", ""),
            entry.get("name", ""),
        )

    def _has_issue(entries: List[dict]) -> bool:
        issue_keys = {
            "warnings",
            "errors",
            "items_failed",
            "logs_missing",
            "pytest_failures",
            "pytest_errors",
        }
        for entry in entries:
            name = entry.get("name", "")
            value = entry.get("value", 0)
            if any(key in name for key in issue_keys) and int(value) > 0:
                return True
        return False

    pipeline_id = os.environ.get("CI_PIPELINE_ID")
    pipeline_url = os.environ.get("CI_PIPELINE_URL")
    commit_sha = os.environ.get("CI_COMMIT_SHA")
    commit_short = os.environ.get("CI_COMMIT_SHORT_SHA", commit_sha[:8] if commit_sha else None)
    project_url = os.environ.get("CI_PROJECT_URL")
    commit_url = f"{project_url}/-/commit/{commit_sha}" if project_url and commit_sha else None

    lines = ["# CI Metrics Summary", ""]

    context_parts = []
    if pipeline_id:
        if pipeline_url:
            context_parts.append(f"Pipeline: [{pipeline_id}]({pipeline_url})")
        else:
            context_parts.append(f"Pipeline: {pipeline_id}")
    if commit_short:
        if commit_url:
            context_parts.append(f"Commit: [{commit_short}]({commit_url})")
        else:
            context_parts.append(f"Commit: {commit_short}")
    if context_parts:
        lines.append(" | ".join(context_parts))
        lines.append("")

    clean = not _has_issue(metrics)
    if clean:
        lines.append("<details><summary>All clean (no errors/warnings)</summary>")
    else:
        lines.append("<details open><summary>CI Metrics (issues present)</summary>")
    lines.append("")

    # Group by stage
    stage_group: Dict[str, List[dict]] = {}
    for entry in sorted(metrics, key=sort_key):
        labels = entry.get("labels", {}) or {}
        stage = labels.get("stage", "-")
        stage_group.setdefault(stage, []).append(entry)

    for stage, entries in stage_group.items():
        stage_issue = _has_issue(entries)
        stage_title = stage
        if stage_links and stage in stage_links:
            stage_title = f"[{stage}]({stage_links[stage]})"
        summary_line = f"<summary>{stage_title}"
        if not stage_issue:
            summary_line += " (clean)"
        summary_line += "</summary>"
        if stage_issue:
            lines.append(f"<details open>{summary_line}")
        else:
            lines.append(f"<details>{summary_line}")
        lines.append("")
        lines.extend([
            "| Tool | Metric | Value | Unit | Labels |",
            "| --- | --- | --- | --- | --- |",
        ])
        for entry in entries:
            labels = entry.get("labels", {}) or {}
            tool = labels.get("tool", "-")
            name = entry.get("name", "-")
            value = entry.get("value", "-")
            unit = entry.get("unit", "-")
            labels_str = _format_label_str(labels)
            lines.append(f"| {tool} | {name} | {value} | {unit} | {labels_str} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("</details>")
    return "\n".join(lines)


def _iverilog_metrics(report_path: Path, stage: str) -> List[dict]:
    entries = _load_report_entries(report_path)
    total = len(entries)
    failed = sum(1 for entry in entries if entry.get("status") != "passed")
    warn_count = 0
    err_count = 0
    missing_logs = 0
    for entry in entries:
        log_path = Path(entry.get("log_path", ""))
        w, e, missing = _count_log_messages(log_path)
        warn_count += w
        err_count += e
        if missing:
            missing_logs += 1

    metrics = [
        _make_metric("iverilog_items_total", total, stage, labels={"tool": "iverilog"}),
        _make_metric("iverilog_items_failed", failed, stage, labels={"tool": "iverilog"}),
        _make_metric("iverilog_warnings", warn_count, stage, labels={"tool": "iverilog"}),
        _make_metric("iverilog_errors", err_count, stage, labels={"tool": "iverilog"}),
    ]
    if missing_logs:
        metrics.append(_make_metric("iverilog_logs_missing", missing_logs, stage, labels={"tool": "iverilog"}))
    return metrics


def _yosys_metrics(report_path: Path, stage: str) -> List[dict]:
    entries = _load_report_entries(report_path)
    total = len(entries)
    failed = sum(1 for entry in entries if entry.get("status") != "passed")
    warn_count = 0
    err_count = 0
    missing_logs = 0
    for entry in entries:
        log_path = Path(entry.get("log_path", ""))
        w, e, missing = _count_log_messages(log_path)
        warn_count += w
        err_count += e
        if missing:
            missing_logs += 1

    metrics = [
        _make_metric("yosys_items_total", total, stage, labels={"tool": "yosys"}),
        _make_metric("yosys_items_failed", failed, stage, labels={"tool": "yosys"}),
        _make_metric("yosys_warnings", warn_count, stage, labels={"tool": "yosys"}),
        _make_metric("yosys_errors", err_count, stage, labels={"tool": "yosys"}),
    ]
    if missing_logs:
        metrics.append(_make_metric("yosys_logs_missing", missing_logs, stage, labels={"tool": "yosys"}))
    return metrics


def _pytest_metrics(junit_path: Path, stage: str) -> List[dict]:
    total = failures = errors = skipped = 0
    missing = False
    if not junit_path.exists():
        missing = True
    else:
        try:
            tree = ET.parse(junit_path)
            root = tree.getroot()
            for testcase in root.iter("testcase"):
                total += 1
                failures += len(testcase.findall("failure"))
                errors += len(testcase.findall("error"))
                skipped += len(testcase.findall("skipped"))
        except ET.ParseError as exc:  # pragma: no cover - defensive
            print(f"Warning: unable to parse JUnit XML {junit_path}: {exc}", file=sys.stderr)
            missing = True

    metrics = [
        _make_metric("pytest_cases_total", total, stage, labels={"tool": "pytest"}),
        _make_metric("pytest_failures", failures, stage, labels={"tool": "pytest"}),
        _make_metric("pytest_errors", errors, stage, labels={"tool": "pytest"}),
        _make_metric("pytest_skipped", skipped, stage, labels={"tool": "pytest"}),
    ]
    if missing:
        metrics.append(_make_metric("pytest_junit_missing", 1, stage, labels={"tool": "pytest"}))
    return metrics


def _trufflehog_metrics(report_path: Path, stage: str) -> List[dict]:
    findings = _load_json_lines_or_list(report_path)
    total = len(findings)
    detectors: Counter[str] = Counter()
    for finding in findings:
        detector = finding.get("DetectorName") or finding.get("Detector") or finding.get("detector") or "unknown"
        detectors[str(detector)] += 1
    metrics = [
        _make_metric("trufflehog_findings_total", total, stage, labels={"tool": "trufflehog"}),
    ]
    for detector, count in sorted(detectors.items()):
        metrics.append(
            _make_metric(
                "trufflehog_findings_by_detector",
                count,
                stage,
                labels={"tool": "trufflehog", "detector": detector},
            )
        )
    return metrics


def _secret_detection_metrics(report_path: Path, stage: str) -> List[dict]:
    if not report_path.exists():
        print(f"Warning: secret detection report not found: {report_path}", file=sys.stderr)
        return []
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"Warning: unable to parse secret detection report {report_path}: {exc}", file=sys.stderr)
        return []
    secrets = payload.get("secrets", [])
    if not isinstance(secrets, list):
        print(f"Warning: secret detection report missing 'secrets' list: {report_path}", file=sys.stderr)
        secrets = []
    total = len(secrets)
    categories: Counter[str] = Counter()
    for secret in secrets:
        category = secret.get("category") or secret.get("kind") or "unknown"
        categories[str(category)] += 1
    metrics = [
        _make_metric("secret_detection_findings_total", total, stage, labels={"tool": "gitlab-secret-detection"}),
    ]
    for category, count in sorted(categories.items()):
        metrics.append(
            _make_metric(
                "secret_detection_findings_by_category",
                count,
                stage,
                labels={"tool": "gitlab-secret-detection", "category": category},
            )
        )
    return metrics


def _sast_metrics(report_path: Path, stage: str) -> List[dict]:
    if not report_path.exists():
        print(f"Warning: SAST report not found: {report_path}", file=sys.stderr)
        return []
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"Warning: unable to parse SAST report {report_path}: {exc}", file=sys.stderr)
        return []
    vulns = payload.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        print(f"Warning: SAST report missing 'vulnerabilities' list: {report_path}", file=sys.stderr)
        vulns = []
    total = len(vulns)
    severity_counts: Counter[str] = Counter()
    for vuln in vulns:
        severity = vuln.get("severity") or "unknown"
        severity_counts[str(severity).lower()] += 1
    metrics = [_make_metric("sast_vulnerabilities_total", total, stage, labels={"tool": "sast"})]
    for severity, count in sorted(severity_counts.items()):
        metrics.append(
            _make_metric(
                "sast_vulnerabilities_by_severity",
                count,
                stage,
                labels={"tool": "sast", "severity": severity},
            )
        )
    return metrics


def _cmd_iverilog(args: argparse.Namespace) -> int:
    metrics = _iverilog_metrics(Path(args.report), args.stage)
    _write_metrics(metrics, Path(args.output))
    return 0


def _cmd_yosys(args: argparse.Namespace) -> int:
    metrics = _yosys_metrics(Path(args.report), args.stage)
    _write_metrics(metrics, Path(args.output))
    return 0


def _cmd_pytest(args: argparse.Namespace) -> int:
    metrics = _pytest_metrics(Path(args.junit), args.stage)
    _write_metrics(metrics, Path(args.output))
    return 0


def _cmd_trufflehog(args: argparse.Namespace) -> int:
    metrics = _trufflehog_metrics(Path(args.report), args.stage)
    _write_metrics(metrics, Path(args.output))
    return 0


def _cmd_secret_detection(args: argparse.Namespace) -> int:
    metrics = _secret_detection_metrics(Path(args.report), args.stage)
    _write_metrics(metrics, Path(args.output))
    return 0


def _cmd_sast(args: argparse.Namespace) -> int:
    metrics = _sast_metrics(Path(args.report), args.stage)
    _write_metrics(metrics, Path(args.output))
    return 0


def _cmd_summary(args: argparse.Namespace) -> int:
    collected: List[dict] = []
    missing_inputs = 0
    for path_str in args.inputs:
        path = Path(path_str)
        metrics = _load_metrics_payload(path)
        if not metrics:
            missing_inputs += 1
        collected.extend(metrics)
    token, header, _ = _resolve_api_auth()
    stage_links: Dict[str, str] = {}
    project_id = os.environ.get("CI_PROJECT_ID")
    pipeline_id = os.environ.get("CI_PIPELINE_ID")
    api = os.environ.get("CI_API_V4_URL", "https://gitlab.com/api/v4")
    if token and header and project_id and pipeline_id:
        stage_links = _fetch_stage_links(project_id, pipeline_id, api, token, header)
    markdown = _format_markdown_summary(collected, stage_links=stage_links)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")
    if args.post_comment:
        _post_mr_comment(markdown)
    if missing_inputs:
        print(f"Warning: {missing_inputs} metrics inputs were missing or empty.", file=sys.stderr)
    return 0


def _find_mr_iid_for_branch(api: str, project_id: str, branch: str, token: str, header: str) -> str | None:  # pragma: no cover - network
    encoded_branch = parse.quote_plus(branch)
    encoded_project = _encode_project(project_id)
    url = f"{api}/projects/{encoded_project}/merge_requests?state=opened&source_branch={encoded_branch}"
    req = request.Request(
        url,
        method="GET",
        headers={
            header: token,
            "Accept": "application/json",
        },
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, list) and data:
                    iid = data[0].get("iid")
                    if iid is not None:
                        return str(iid)
            else:
                print(f"Warning: MR lookup for branch '{branch}' returned status {resp.status}", file=sys.stderr)
    except error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        detail = f"HTTP {exc.code}"
        if body:
            detail = f"{detail}: {body}"
        print(f"Warning: failed to look up MR for branch '{branch}': {detail}", file=sys.stderr)
    except error.URLError as exc:
        print(f"Warning: unable to reach GitLab API for MR lookup (branch '{branch}'): {exc}", file=sys.stderr)
    return None


def _post_mr_comment(body: str) -> bool:  # pragma: no cover - network
    project_id = os.environ.get("CI_PROJECT_ID")
    mr_iid = os.environ.get("CI_MERGE_REQUEST_IID")
    branch = os.environ.get("CI_COMMIT_BRANCH")
    api = os.environ.get("CI_API_V4_URL", "https://gitlab.com/api/v4")
    token, header_name, source = _resolve_api_auth()

    if not project_id:
        print("Info: CI_PROJECT_ID not set; skipping MR comment.", file=sys.stderr)
        return False
    if not token:
        print("Warning: MR_COMMENT_TOKEN/CI_JOB_TOKEN missing; cannot post MR comment.", file=sys.stderr)
        return False
    if not mr_iid and branch:
        mr_iid = _find_mr_iid_for_branch(api, project_id, branch, token, header_name)
    if not mr_iid:
        print("Info: MR context not detected; skipping comment.", file=sys.stderr)
        return False

    encoded_project = _encode_project(project_id)
    url = f"{api}/projects/{encoded_project}/merge_requests/{mr_iid}/notes"
    data = json.dumps({"body": body}).encode("utf-8")
    req = request.Request(
        url,
        data=data,
        method="POST",
        headers={
            header_name: token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                return True
            print(f"Warning: posting MR comment returned status {resp.status}", file=sys.stderr)
    except error.HTTPError as exc:
        print(f"Warning: failed to post MR comment: {exc}", file=sys.stderr)
    except error.URLError as exc:
        print(f"Warning: failed to reach GitLab API: {exc}", file=sys.stderr)
    return False


def _cmd_comment(args: argparse.Namespace) -> int:
    summary_path = Path(args.summary)
    if not summary_path.exists():
        print(f"Warning: summary not found: {summary_path}", file=sys.stderr)
        return 0
    body = summary_path.read_text(encoding="utf-8")
    _post_mr_comment(body)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Emit GitLab metrics reports from CI logs.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    iverilog = subparsers.add_parser("iverilog", help="Generate metrics from iverilog report JSON.")
    iverilog.add_argument("--report", required=True, help="Path to iverilog_*_report.json")
    iverilog.add_argument("--stage", required=True, help="Stage label (e.g., compile or elaborate).")
    iverilog.add_argument("--output", required=True, help="Path to write metrics JSON.")
    iverilog.set_defaults(func=_cmd_iverilog)

    yosys = subparsers.add_parser("yosys", help="Generate metrics from yosys report JSON.")
    yosys.add_argument("--report", required=True, help="Path to yosys_runs_report.json")
    yosys.add_argument("--stage", required=True, help="Stage label (e.g., synth).")
    yosys.add_argument("--output", required=True, help="Path to write metrics JSON.")
    yosys.set_defaults(func=_cmd_yosys)

    pytest_parser = subparsers.add_parser("pytest", help="Generate metrics from pytest JUnit XML.")
    pytest_parser.add_argument("--junit", required=True, help="Path to pytest JUnit XML report.")
    pytest_parser.add_argument("--stage", required=True, help="Stage label (e.g., test).")
    pytest_parser.add_argument("--output", required=True, help="Path to write metrics JSON.")
    pytest_parser.set_defaults(func=_cmd_pytest)

    trufflehog = subparsers.add_parser("trufflehog", help="Generate metrics from trufflehog JSON/NDJSON output.")
    trufflehog.add_argument("--report", required=True, help="Path to trufflehog JSON report.")
    trufflehog.add_argument("--stage", required=True, help="Stage label (e.g., secret-detection).")
    trufflehog.add_argument("--output", required=True, help="Path to write metrics JSON.")
    trufflehog.set_defaults(func=_cmd_trufflehog)

    secret_detection = subparsers.add_parser("secret-detection", help="Generate metrics from GitLab secret detection report.")
    secret_detection.add_argument("--report", required=True, help="Path to gl-secret-detection-report.json.")
    secret_detection.add_argument("--stage", required=True, help="Stage label (e.g., secret-detection).")
    secret_detection.add_argument("--output", required=True, help="Path to write metrics JSON.")
    secret_detection.set_defaults(func=_cmd_secret_detection)

    sast_parser = subparsers.add_parser("sast", help="Generate metrics from GitLab SAST report.")
    sast_parser.add_argument("--report", required=True, help="Path to gl-sast-report.json.")
    sast_parser.add_argument("--stage", required=True, help="Stage label (e.g., secret-detection).")
    sast_parser.add_argument("--output", required=True, help="Path to write metrics JSON.")
    sast_parser.set_defaults(func=_cmd_sast)

    summary = subparsers.add_parser("summary", help="Render a markdown summary from metrics JSON files.")
    summary.add_argument("--inputs", nargs="+", required=True, help="List of metrics JSON files.")
    summary.add_argument("--output", required=True, help="Path to write markdown summary.")
    summary.add_argument("--post-comment", action="store_true", help="Post the summary as an MR note when CI variables are available.")
    summary.set_defaults(func=_cmd_summary)

    comment = subparsers.add_parser("comment", help="Post a markdown summary as an MR note.")
    comment.add_argument("--summary", required=True, help="Path to markdown summary.")
    comment.set_defaults(func=_cmd_comment)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
