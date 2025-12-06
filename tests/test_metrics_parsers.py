from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tools.metrics as metrics


def test_trufflehog_metrics_ndjson(tmp_path: Path) -> None:
    report = tmp_path / "trufflehog.json"
    report.write_text(
        '\n'.join(
            [
                '{"DetectorName":"aws","Verified":true}',
                '{"Detector":"gcp","Verified":false}',
            ]
        ),
        encoding="utf-8",
    )
    results = metrics._trufflehog_metrics(report, "secret-detection")
    by_name = {entry["name"]: entry for entry in results}
    assert by_name["trufflehog_findings_total"]["value"] == 2
    detector_labels = {entry["labels"]["detector"] for entry in results if entry["name"] == "trufflehog_findings_by_detector"}
    assert {"aws", "gcp"} <= detector_labels


def test_secret_detection_metrics_categories(tmp_path: Path) -> None:
    report = tmp_path / "gl-secret-detection-report.json"
    report.write_text(
        '{"secrets":[{"category":"token"},{"kind":"password"},{"category":""}]}',
        encoding="utf-8",
    )
    metrics_list = metrics._secret_detection_metrics(report, "secret-detection")
    by_name = {m["name"]: m for m in metrics_list}
    assert by_name["secret_detection_findings_total"]["value"] == 3
    categories = {(m["labels"]["category"], m["value"]) for m in metrics_list if m["name"] == "secret_detection_findings_by_category"}
    assert ("token", 1) in categories
    assert ("password", 1) in categories
    assert ("unknown", 1) in categories


def test_secret_detection_missing_file_returns_empty(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    assert metrics._secret_detection_metrics(missing, "secret-detection") == []


def test_sast_metrics_severity_counts(tmp_path: Path) -> None:
    report = tmp_path / "gl-sast-report.json"
    report.write_text(
        '{"vulnerabilities":[{"severity":"High"},{"severity":"low"},{"severity":""}]}',
        encoding="utf-8",
    )
    metrics_list = metrics._sast_metrics(report, "secret-detection")
    by_name = {m["name"]: m for m in metrics_list}
    assert by_name["sast_vulnerabilities_total"]["value"] == 3
    severities = {(m["labels"]["severity"], m["value"]) for m in metrics_list if m["name"] == "sast_vulnerabilities_by_severity"}
    assert ("high", 1) in severities
    assert ("low", 1) in severities
    assert ("unknown", 1) in severities


def test_load_json_lines_or_list_handles_ndjson(tmp_path: Path) -> None:
    report = tmp_path / "mixed.json"
    report.write_text('{"a":1}\n{"b":2}', encoding="utf-8")
    items = metrics._load_json_lines_or_list(report)
    assert len(items) == 2
    assert items[0]["a"] == 1 and items[1]["b"] == 2


def test_cmd_summary_warns_on_missing_inputs(tmp_path: Path, capsys) -> None:
    src = tmp_path / "metrics.json"
    src.write_text('{"metrics":[{"name":"foo","value":1,"labels":{"stage":"compile"}}]}', encoding="utf-8")
    out = tmp_path / "summary.md"
    args = argparse.Namespace(inputs=[str(src), str(tmp_path / "missing.json")], output=str(out), post_comment=False)
    rc = metrics._cmd_summary(args)
    captured = capsys.readouterr()
    assert rc == 0
    assert "missing or empty" in captured.err
    assert out.exists()


def test_count_and_load_helpers(tmp_path: Path, capsys) -> None:
    log = tmp_path / "log.txt"
    log.write_text("warning: foo\nfatal error\n", encoding="utf-8")
    warnings, errors, missing = metrics._count_log_messages(log)
    assert warnings == 1 and errors == 1 and not missing

    missing_log = tmp_path / "missing.log"
    warnings, errors, missing = metrics._count_log_messages(missing_log)
    assert missing and warnings == 0 and errors == 0

    non_list_report = tmp_path / "report.json"
    non_list_report.write_text('{"not":"list"}', encoding="utf-8")
    metrics._load_report_entries(non_list_report)
    captured = capsys.readouterr()
    assert "not a list" in captured.err

    metrics_payload = tmp_path / "metrics.json"
    metrics._write_metrics([metrics._make_metric("x", 1, "stage")], metrics_payload)
    loaded = metrics._load_metrics_payload(metrics_payload)
    assert loaded[0]["name"] == "x"


def test_markdown_summary_and_label_str(tmp_path: Path) -> None:
    entries = [
        metrics._make_metric("warnings", 1, "compile", labels={"tool": "iverilog", "extra": "y"}),
        metrics._make_metric("items_failed", 0, "compile", labels={"tool": "iverilog"}),
    ]
    summary = metrics._format_markdown_summary(entries, stage_links={"compile": "http://example.com"})
    assert "issues present" in summary
    assert "extra=y" in summary


def test_eda_and_pytest_metrics(tmp_path: Path) -> None:
    log = tmp_path / "log.txt"
    log.write_text("warning here\nerror here\n", encoding="utf-8")
    report = tmp_path / "iverilog.json"
    missing_log = tmp_path / "does_not_exist.log"
    report.write_text(
        '[{"status":"passed","log_path":"%s"},{"status":"failed","log_path":"%s"},{"status":"failed","log_path":"%s"}]'
        % (log, log, missing_log),
        encoding="utf-8",
    )
    iv_metrics = metrics._iverilog_metrics(report, "compile")
    names = {m["name"]: m["value"] for m in iv_metrics}
    assert names["iverilog_items_total"] == 3
    assert names["iverilog_items_failed"] == 2

    yosys_report = tmp_path / "yosys.json"
    yosys_report.write_text('[{"status":"passed","log_path":"%s"},{"status":"failed","log_path":"%s"}]' % (log, missing_log), encoding="utf-8")
    yosys_metrics = metrics._yosys_metrics(yosys_report, "synth")
    assert any(m["name"] == "yosys_warnings" for m in yosys_metrics)

    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuite><testcase name="a"><failure/></testcase><testcase name="b"><skipped/></testcase></testsuite>',
        encoding="utf-8",
    )
    py_metrics = metrics._pytest_metrics(junit, "test")
    name_map = {m["name"]: m["value"] for m in py_metrics}
    assert name_map["pytest_cases_total"] == 2
    assert name_map["pytest_failures"] == 1
    assert name_map["pytest_skipped"] == 1


def test_cmd_interfaces(tmp_path: Path) -> None:
    log = tmp_path / "log.txt"
    log.write_text("", encoding="utf-8")
    rep = tmp_path / "rep.json"
    rep.write_text('[{"status":"passed","log_path":"%s"}]' % log, encoding="utf-8")
    out = tmp_path / "out.json"

    args = argparse.Namespace(report=str(rep), stage="compile", output=str(out))
    assert metrics._cmd_iverilog(args) == 0
    assert out.exists()

    args.stage = "synth"
    assert metrics._cmd_yosys(args) == 0

    junit = tmp_path / "junit.xml"
    junit.write_text("<testsuite></testsuite>", encoding="utf-8")
    args = argparse.Namespace(junit=str(junit), stage="test", output=str(out))
    assert metrics._cmd_pytest(args) == 0

    args = argparse.Namespace(report=str(rep), stage="secret", output=str(out))
    metrics._cmd_trufflehog(args)

    secret_report = tmp_path / "secret.json"
    secret_report.write_text('{"secrets":[{"category":"token"}]}', encoding="utf-8")
    args = argparse.Namespace(report=str(secret_report), stage="secret-detection", output=str(out))
    metrics._cmd_secret_detection(args)

    sast_report = tmp_path / "sast.json"
    sast_report.write_text('{"vulnerabilities":[{"severity":"HIGH"}]}', encoding="utf-8")
    args = argparse.Namespace(report=str(sast_report), stage="secret-detection", output=str(out))
    metrics._cmd_sast(args)

    summary_md = tmp_path / "summary.md"
    args = argparse.Namespace(inputs=[str(out)], output=str(summary_md), post_comment=False)
    metrics._cmd_summary(args)
    assert summary_md.exists()

    missing_summary = tmp_path / "missing.md"
    args = argparse.Namespace(summary=str(missing_summary))
    metrics._cmd_comment(args)


def test_build_arg_parser_executes_main(tmp_path: Path, monkeypatch) -> None:
    metrics_file = tmp_path / "m.json"
    metrics._write_metrics([metrics._make_metric("x", 1, "s")], metrics_file)
    output_md = tmp_path / "out.md"
    parser = metrics.build_arg_parser()
    args = parser.parse_args(["summary", "--inputs", str(metrics_file), "--output", str(output_md)])
    assert args.func(args) == 0
    assert output_md.exists()

    # exercise main entry with env to drive stage_links path
    monkeypatch.setenv("CI_PIPELINE_ID", "123")
    monkeypatch.setenv("CI_PROJECT_ID", "42")
    monkeypatch.setenv("CI_API_V4_URL", "https://gitlab.example/api/v4")
    monkeypatch.setenv("CI_JOB_TOKEN", "jobtoken")
    assert metrics.main(["summary", "--inputs", str(metrics_file), "--output", str(output_md)]) == 0

    # _cmd_comment with existing summary
    args = argparse.Namespace(summary=str(output_md))
    metrics._cmd_comment(args)

    # summary with post_comment (patched)
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "1")
    monkeypatch.setenv("CI_COMMIT_BRANCH", "test")
    monkeypatch.setenv("CI_PROJECT_URL", "http://ci/proj")
    monkeypatch.setattr(metrics, "_post_mr_comment", lambda body: True)
    args = argparse.Namespace(inputs=[str(metrics_file)], output=str(output_md), post_comment=True)
    metrics._cmd_summary(args)


def test_missing_and_invalid_inputs(tmp_path: Path, monkeypatch, capsys) -> None:
    missing_report = tmp_path / "missing.json"
    metrics._load_report_entries(missing_report)
    metrics._load_json_lines_or_list(missing_report)
    invalid_lines = tmp_path / "invalid.ndjson"
    invalid_lines.write_text(' \nnot-json\n{"ok":1}', encoding="utf-8")
    metrics._load_json_lines_or_list(invalid_lines)

    metrics._load_metrics_payload(missing_report)
    bad_metrics = tmp_path / "bad_metrics.json"
    bad_metrics.write_text('{"metrics": "oops"}', encoding="utf-8")
    metrics._load_metrics_payload(bad_metrics)

    invalid_secret = tmp_path / "bad_secret.json"
    invalid_secret.write_text('{"secrets":"oops"}', encoding="utf-8")
    metrics._secret_detection_metrics(invalid_secret, "secret")
    invalid_secret.write_text("not-json", encoding="utf-8")
    metrics._secret_detection_metrics(invalid_secret, "secret")

    invalid_sast = tmp_path / "bad_sast.json"
    invalid_sast.write_text('{"vulnerabilities": "oops"}', encoding="utf-8")
    metrics._sast_metrics(invalid_sast, "secret")
    invalid_sast.write_text("not-json", encoding="utf-8")
    metrics._sast_metrics(invalid_sast, "secret")
    missing_sast = tmp_path / "missing_sast.json"
    metrics._sast_metrics(missing_sast, "secret")

    monkeypatch.delenv("MR_COMMENT_TOKEN", raising=False)
    monkeypatch.delenv("CI_JOB_TOKEN", raising=False)
    assert metrics._resolve_api_auth() == (None, "", "")
    monkeypatch.setenv("CI_JOB_TOKEN", "jobtok")
    assert metrics._resolve_api_auth()[1] == "JOB-TOKEN"
    monkeypatch.setenv("MR_COMMENT_TOKEN", "pattok")
    assert metrics._resolve_api_auth()[1] == "PRIVATE-TOKEN"

    blank_summary = metrics._format_markdown_summary([])
    assert "No metrics available" in blank_summary

    metrics._cmd_comment(argparse.Namespace(summary=str(missing_report)))

    missing_junit = tmp_path / "missing.xml"
    py_metrics = metrics._pytest_metrics(missing_junit, "test")
    assert any(m["name"] == "pytest_junit_missing" for m in py_metrics)

    captured = capsys.readouterr()
    assert "report not found" in captured.err or "metrics file not found" in captured.err


def test_format_markdown_summary_env(monkeypatch) -> None:
    monkeypatch.setenv("CI_PIPELINE_ID", "123")
    monkeypatch.setenv("CI_PIPELINE_URL", "http://ci/p/123")
    monkeypatch.setenv("CI_COMMIT_SHA", "abcdef012345")
    monkeypatch.setenv("CI_PROJECT_URL", "http://ci/proj")
    metrics_list = [
        metrics._make_metric("warnings", 0, "compile", labels={"tool": "iverilog"}),
        metrics._make_metric("errors", 1, "compile", labels={"tool": "iverilog"}),
    ]
    rendered = metrics._format_markdown_summary(metrics_list, stage_links={"compile": "http://job"})
    assert "Pipeline:" in rendered
    assert "issues present" in rendered

    monkeypatch.delenv("CI_PROJECT_URL", raising=False)
    rendered_no_commit_url = metrics._format_markdown_summary(metrics_list)
    assert "Commit: [abcdef01]" not in rendered_no_commit_url
