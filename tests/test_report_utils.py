import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from tools import report_utils

def create_dep_file(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "deps.d"
    path.write_text(content)
    return path


def test_normalize_tokens_filters_blanks() -> None:
    tokens = [" foo ", "", "foo", "bar"]
    assert report_utils._normalize_tokens(tokens) == ["foo", "bar"]


def test_parse_dep_file_with_colon(tmp_path: Path) -> None:
    dep_file = create_dep_file(tmp_path, "target.o: foo.v bar.v baz.v\n")
    assert report_utils.parse_dep_file(dep_file) == ["foo.v", "bar.v", "baz.v"]


def test_parse_dep_file_without_colon(tmp_path: Path) -> None:
    dep_file = create_dep_file(tmp_path, "foo.v \\\n bar.v\nfoo.v\n")
    assert report_utils.parse_dep_file(dep_file) == ["foo.v", "bar.v"]


def test_parse_dep_file_missing(tmp_path: Path) -> None:
    assert report_utils.parse_dep_file(tmp_path / "missing.d") == []


def test_build_iverilog_entry(tmp_path: Path) -> None:
    log_path = tmp_path / "log.txt"
    log_path.write_text("warning\n")
    dep_path = create_dep_file(tmp_path, "out: a.v\n")
    entry = report_utils.build_iverilog_entry(
        source="a.v",
        mode="compile",
        status="passed",
        command="iverilog -tnull",
        log_path=log_path,
        dep_path=dep_path,
        output_artifact=None,
    )
    assert entry["dependencies"] == ["a.v"]
    assert entry["log_size_bytes"] == log_path.stat().st_size


def test_build_iverilog_entry_with_output(tmp_path: Path) -> None:
    log_path = tmp_path / "log.txt"
    log_path.touch()
    entry = report_utils.build_iverilog_entry(
        source="a.v",
        mode="elaborate",
        status="failed",
        command="iverilog",
        log_path=log_path,
        dep_path=None,
        output_artifact="out.vvp",
    )
    assert entry["output_artifact"] == "out.vvp"


def test_build_yosys_entry(tmp_path: Path) -> None:
    log_path = tmp_path / "yosys.log"
    log_path.write_text("log")
    entry = report_utils.build_yosys_entry(
        source="a.v",
        status="failed",
        command="yosys -p script",
        log_path=log_path,
        output_artifact="out.json",
    )
    assert entry["output_artifact"] == "out.json"


def test_append_and_convert_jsonl(tmp_path: Path) -> None:
    jsonl = tmp_path / "data.jsonl"
    entry = {"hello": "world"}
    report_utils.append_jsonl_entry(jsonl, entry)
    output = tmp_path / "data.json"
    report_utils.jsonl_to_json(jsonl, output)
    assert json.loads(output.read_text()) == [entry]


def test_extract_yosys_stat_json(tmp_path: Path) -> None:
    log_path = tmp_path / "stat.log"
    log_path.write_text("prefix\n{\"a\": 1}\ntrailer")
    assert report_utils.extract_yosys_stat_json(log_path) == {"a": 1}


def test_extract_yosys_stat_json_error(tmp_path: Path) -> None:
    log_path = tmp_path / "bad.log"
    log_path.write_text("no json here")
    with pytest.raises(ValueError):
        report_utils.extract_yosys_stat_json(log_path)


def test_write_yosys_summary(tmp_path: Path) -> None:
    log_path = tmp_path / "stat.log"
    log_path.write_text("--\n{\"a\": 1}\n--")
    out_path = tmp_path / "summary.json"
    assert report_utils.write_yosys_summary(log_path, out_path)
    assert json.loads(out_path.read_text()) == {"a": 1}


def test_write_yosys_summary_missing_ok(tmp_path: Path) -> None:
    out_path = tmp_path / "summary.json"
    assert not report_utils.write_yosys_summary(tmp_path / "missing.log", out_path, missing_ok=True)
    assert not out_path.exists()


def test_write_yosys_summary_missing_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        report_utils.write_yosys_summary(tmp_path / "missing.log", tmp_path / "summary.json")


def test_cli_iverilog_entry_and_convert(tmp_path: Path) -> None:
    jsonl = tmp_path / "iverilog.jsonl"
    log_path = tmp_path / "log"
    log_path.write_text("log")
    dep_path = create_dep_file(tmp_path, "foo.v\n")
    argv = [
        "iverilog-entry",
        "--jsonl",
        str(jsonl),
        "--source",
        "foo.v",
        "--mode",
        "compile",
        "--status",
        "passed",
        "--command",
        "iverilog",
        "--log-path",
        str(log_path),
        "--dep-path",
        str(dep_path),
    ]
    assert report_utils.main(argv) == 0
    assert jsonl.exists()
    output = tmp_path / "iverilog.json"
    report_utils.main([
        "jsonl-to-json",
        "--input",
        str(jsonl),
        "--output",
        str(output),
    ])
    assert json.loads(output.read_text())[0]["source"] == "foo.v"


def test_cli_yosys_entry(tmp_path: Path) -> None:
    jsonl = tmp_path / "yosys.jsonl"
    log_path = tmp_path / "log"
    log_path.write_text("log")
    argv = [
        "yosys-entry",
        "--jsonl",
        str(jsonl),
        "--source",
        "foo.v",
        "--status",
        "failed",
        "--command",
        "yosys",
        "--log-path",
        str(log_path),
        "--output-artifact",
        "out.json",
    ]
    assert report_utils.main(argv) == 0
    stored = jsonl.read_text().strip().splitlines()
    assert len(stored) == 1


def test_cli_yosys_summary_missing_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv = [
        "yosys-summary",
        "--log",
        str(tmp_path / "missing.log"),
        "--output",
        str(tmp_path / "summary.json"),
        "--missing-ok",
    ]
    assert report_utils.main(argv) == 0
    assert tmp_path.joinpath("summary.json").exists() is False
    assert "Warning" in capsys.readouterr().err


def test_cli_yosys_summary_bad_json_missing_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log_path = tmp_path / "bad.log"
    log_path.write_text("no json")
    argv = [
        "yosys-summary",
        "--log",
        str(log_path),
        "--output",
        str(tmp_path / "summary.json"),
        "--missing-ok",
    ]
    assert report_utils.main(argv) == 0
    captured = capsys.readouterr()
    assert "Unable to locate JSON" in captured.err


def test_cli_yosys_summary_bad_json_error(tmp_path: Path) -> None:
    log_path = tmp_path / "bad.log"
    log_path.write_text("no json")
    with pytest.raises(ValueError):
        report_utils.main([
            "yosys-summary",
            "--log",
            str(log_path),
            "--output",
            str(tmp_path / "summary.json"),
        ])


def test_cli_yosys_summary_success(tmp_path: Path) -> None:
    log_path = tmp_path / "stat.log"
    log_path.write_text("header{\"ok\":true}footer")
    out_path = tmp_path / "summary.json"
    assert report_utils.main([
        "yosys-summary",
        "--log",
        str(log_path),
        "--output",
        str(out_path),
    ]) == 0
    assert json.loads(out_path.read_text()) == {"ok": True}

def test_aggregate_yosys_stats(tmp_path: Path) -> None:
    stat1 = tmp_path / "a.stat.json"
    stat2 = tmp_path / "b.stat.json"
    stat1.write_text(json.dumps({"modules": {"top": {}}}))
    stat2.write_text(json.dumps({"modules": {"other": {}}}))
    result = report_utils.aggregate_yosys_stats([stat1, stat2, tmp_path / "missing.json"])
    assert [entry["source"] for entry in result] == ["a", "b"]


def test_cli_aggregate_yosys_stats(tmp_path: Path) -> None:
    stat1 = tmp_path / "a.stat.json"
    stat1.write_text(json.dumps({"modules": {"top": {}}}))
    output = tmp_path / "summary.json"
    assert report_utils.main([
        "aggregate-yosys-stats",
        "--inputs",
        str(stat1),
        "--output",
        str(output),
    ]) == 0
    data = json.loads(output.read_text())
    assert data[0]["source"] == "a"
