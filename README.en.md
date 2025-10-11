# hdlbits

Workspace for managing HDLBits Verilog practice solutions with automated verification. When you add a new `.v` file, the CI pipeline runs syntax checks, elaboration, synthesis, and Python unit tests, then publishes the results as artifacts.

## Components

- `scripts/generate_filelists.py`: Scans `v/` for Verilog sources and writes them to `listfile/rtl.f`.
- `scripts/run_iverilog_checks.sh`: Compiles and elaborates each source with `iverilog`, saving logs and dependency files in `build/`.
- `scripts/run_yosys_synth.sh`: Synthesizes each source with `yosys`, generating netlists in `build/synth/` and summary reports in `build/reports/`.
- `tools/report_utils.py`: Shared reporting helpers used by the scripts; kept at 100% test coverage.

## Quick Start

1. **Install prerequisites**: [`uv`](https://docs.astral.sh/uv/) ≥ 0.4, `iverilog`, `yosys`.
2. **Set up the Python environment**:
   ```bash
   uv venv py312 --python=3.12.11
   source py312/bin/activate
   uv pip install pytest pytest-cov
   ```
3. **Run the verification flow**:
   ```bash
   python scripts/generate_filelists.py
   ./scripts/run_iverilog_checks.sh listfile/rtl.f compile
   ./scripts/run_iverilog_checks.sh listfile/rtl.f elaborate
   ./scripts/run_yosys_synth.sh listfile/rtl.f
   pytest --cov=tools --cov-report=term --cov-fail-under=100
   ```
   Logs and reports are written to `build/` and `coverage.xml`.

## CI Pipeline Overview

GitLab CI runs the jobs in this order:

1. `generate:filelist` – build the Verilog manifest
2. `compile:iverilog` – syntax/SystemVerilog option checks
3. `elaborate:iverilog` – elaborate by producing a VVP output
4. `synth:yosys` – generate netlists and statistics
5. `unit:test` – Python utility tests and coverage gate
6. `secret-detection` – GitLab secret scanning template

Each job uploads `build/reports/` artifacts regardless of success and reuses the same scripts as local workflows.

## Directory Overview

- `v/`: Verilog solutions for HDLBits problems
- `scripts/`: Automation scripts invoked by CI
- `tools/`: Python utilities for report generation
- `tests/`: Pytest suite covering the `tools/` modules
- `listfile/`, `build/`: Generated outputs from scripts and CI runs

You can use `uv run` to execute commands without activating the virtual environment, and cleaning `build/` and `listfile/` before reruns keeps results aligned with CI expectations.
