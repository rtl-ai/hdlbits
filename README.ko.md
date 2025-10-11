# hdlbits

Verilog 연습 문제 풀이를 자동화된 검증 파이프라인으로 관리하는 워크스페이스입니다. 새 `.v` 파일을 추가하면 CI가 구문 검사부터 합성, Python 유닛 테스트까지 실행해 결과를 아티팩트로 남깁니다.

## 구성 요소

- `scripts/generate_filelists.py`: `v/` 아래의 Verilog 파일을 찾아 `listfile/rtl.f`에 기록합니다.
- `scripts/run_iverilog_checks.sh`: 각 소스를 `iverilog`로 컴파일/엘라보레이트하여 로그와 의존성 정보를 `build/`에 저장합니다.
- `scripts/run_yosys_synth.sh`: 개별 소스를 `yosys`로 합성해 넷리스트(`build/synth/`)와 요약 리포트(`build/reports/`)를 생성합니다.
- `tools/report_utils.py`: 위 스크립트에서 공통으로 사용하는 리포트/요약 유틸리티를 제공하며, 100% 커버리지 테스트를 유지합니다.

## 빠른 시작

1. **필수 도구 설치**: [`uv`](https://docs.astral.sh/uv/) ≥ 0.4, `iverilog`, `yosys`를 준비합니다.
2. **Python 환경 준비**:
   ```bash
   uv venv py312 --python=3.12.11
   source py312/bin/activate
   uv pip install pytest pytest-cov
   ```
3. **검증 실행**:
   ```bash
   python scripts/generate_filelists.py
   ./scripts/run_iverilog_checks.sh listfile/rtl.f compile
   ./scripts/run_iverilog_checks.sh listfile/rtl.f elaborate
   ./scripts/run_yosys_synth.sh listfile/rtl.f
   pytest --cov=tools --cov-report=term --cov-fail-under=100
   ```
   로그와 리포트는 `build/` 및 `coverage.xml`에 생성됩니다.

## CI 파이프라인 개요

GitLab CI는 다음 순서로 실행됩니다.

1. `generate:filelist` – Verilog 파일 목록 생성
2. `compile:iverilog` – 구문/SV 옵션 검사
3. `elaborate:iverilog` – VVP 생성으로 엘라보레이션 확인
4. `synth:yosys` – 넷리스트 및 통계 산출
5. `unit:test` – Python 유틸리티 테스트 및 커버리지 확인
6. `secret-detection` – GitLab 제공 시크릿 검사용 템플릿

각 단계는 실패 여부와 무관하게 `build/reports/` 아티팩트를 업로드하며, 로컬 실행과 동일한 스크립트를 사용합니다.

## 디렉터리 개요

- `v/`: HDLBits 문제 풀이용 Verilog 소스
- `scripts/`: CI에서 호출하는 자동화 스크립트
- `tools/`: 리포트 생성 등 Python 유틸리티 모듈
- `tests/`: `tools/` 모듈을 검증하는 pytest 스위트
- `listfile/`, `build/`: 스크립트와 CI 실행 결과가 저장되는 산출물 디렉터리

필요 시 `uv run`을 이용해 가상환경 활성화 없이 명령을 실행할 수 있으며, 작업 전후로 `build/`와 `listfile/`을 정리하면 CI 결과와 동일한 상태를 유지할 수 있습니다.
