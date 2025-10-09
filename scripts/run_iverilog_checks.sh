#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/run_iverilog_checks.sh [manifest] [mode]
#   manifest: path to file list (default: listfile/rtl.f)
#   mode: compile or elaborate (default: compile)
#
# The compile mode runs `iverilog -tnull` on each entry to perform a syntax check.
# The elaborate mode produces a temporary VVP output to ensure the design can be elaborated.

manifest="${1:-listfile/rtl.f}"
mode="${2:-compile}"

if [[ ! -f "${manifest}" ]]; then
  echo "Manifest not found: ${manifest}" >&2
  exit 1
fi

case "${mode}" in
  compile)
    echo "Running iverilog syntax checks using ${manifest}"
    while IFS= read -r src; do
      [[ -z "${src}" ]] && continue
      echo "  -> iverilog -tnull ${src}"
      iverilog -g2012 -tnull "${src}"
    done < "${manifest}"
    ;;
  elaborate)
    echo "Running iverilog elaboration checks using ${manifest}"
    build_dir="build/elab"
    mkdir -p "${build_dir}"
    while IFS= read -r src; do
      [[ -z "${src}" ]] && continue
      stem="$(basename "${src}" .v)"
      out="${build_dir}/${stem}.vvp"
      echo "  -> iverilog -o ${out} ${src}"
      iverilog -g2012 -o "${out}" "${src}"
    done < "${manifest}"
    ;;
  *)
    echo "Unsupported mode: ${mode}" >&2
    exit 1
    ;;
esac
