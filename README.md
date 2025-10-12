# hdlbits

Automated verification workspace for HDLBits Verilog practice. Every new `.v` file
flows through syntax checks, elaboration, synthesis, and Python unit tests via the
GitLab CI pipeline described in the full documentation.

## Documentation

- [English guide](README.en.md) – components, quick start, and CI pipeline details
- [한국어 가이드](README.ko.md) – 구성 요소와 로컬/CI 흐름을 한국어로 정리

## At a Glance

- Source files live under `v/` and are discovered automatically for CI runs.
- Automation scripts and reporting utilities reside in `scripts/` and `tools/`.
- Generated artifacts land in `build/` and `listfile/` both locally and in CI.

For contribution guidelines or additional languages, update this index alongside the
localized documents.
