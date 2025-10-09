# hdlbits

## CI automation overview

- `scripts/generate_filelists.py` 스크립트는 `v/` 디렉터리의 Verilog 소스 목록을 자동으로 생성해 `listfile/rtl.f`를 최신 상태로 유지합니다.
- `scripts/run_iverilog_checks.sh`는 `iverilog`를 이용해 컴파일/엘라보레이션을 수행하고, 결과를 `build/reports/iverilog_*.json`으로 요약합니다. 각 실행 로그와 의존성(`*.d`) 정보가 함께 기록됩니다.
- `scripts/run_yosys_synth.sh`는 각 Verilog 소스를 개별적으로 합성하고 `build/synth/*.json` 넷리스트와 `build/reports/*.stat.json` 통계를 생성합니다. 모든 결과는 `build/reports/yosys_runs_report.json` 및 `build/reports/yosys_synth_summary.json`으로 집계됩니다.
- `tools/report_utils.py` 모듈은 위 스크립트들이 호출하는 공용 도움 함수를 제공하며, `pytest --cov=tools --cov-fail-under=100`으로 100% 커버리지 테스트를 유지합니다.
- GitLab CI 파이프라인은 `generate -> compile -> elaborate -> synth -> unit:test` 순으로 실행되며, 모든 단계에서 `uv venv py312 --python=3.12.11`로 생성한 임시 환경을 사용해 Python 유틸리티를 실행합니다. 실패 여부와 관계없이 `build/reports/` 아티팩트를 업로드합니다.

## Local development workflow

CI와 동일하게 `uv` 기반 Python 3.12 환경을 사용하여 툴링을 실행하세요.

### 1. Prerequisites

- [`uv`](https://docs.astral.sh/uv/) 0.4 이상
- `iverilog`, `yosys` (패키지 매니저나 사내 이미지에 설치되어 있어야 합니다)

### 2. Create or refresh the virtual environment

```bash
uv venv py312 --python=3.12.11
source py312/bin/activate
uv pip install pytest pytest-cov
```

위 명령은 로컬 디렉터리에 `py312/` 가상환경을 만들고, 테스트 스위트에 필요한 Python 패키지를 설치합니다. 이미 환경이 있다면 `uv venv ...` 명령은 Python 버전만 확인하고 그대로 둡니다.

환경을 활성화하지 않고 실행하려면 `uv run --python py312/bin/python <command>` 형태로 대체할 수도 있습니다.

### 3. Run HDL automation scripts

```bash
python scripts/generate_filelists.py
./scripts/run_iverilog_checks.sh listfile/rtl.f compile
./scripts/run_iverilog_checks.sh listfile/rtl.f elaborate
./scripts/run_yosys_synth.sh listfile/rtl.f
```

각 스크립트는 `build/`와 `listfile/` 아래에 결과물을 생성하므로, 새로운 run 전에 필요하다면 디렉터리를 정리하세요.

### 4. Execute unit tests

```bash
pytest --cov=tools --cov-report=term --cov-fail-under=100
```

가상환경을 비활성화하려면 `deactivate`를 실행하면 됩니다.
