#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/run_yosys_synth.sh [manifest]
#   manifest: path to file list (default: listfile/rtl.f)
#
# Runs a lightweight synthesis flow per HDL source using Yosys to ensure the
# design is structurally valid.

manifest="${1:-listfile/rtl.f}"

if [[ ! -f "${manifest}" ]]; then
  echo "Manifest not found: ${manifest}" >&2
  exit 1
fi

out_dir="build/synth"
mkdir -p "${out_dir}"

while IFS= read -r src; do
  [[ -z "${src}" ]] && continue
  stem="$(basename "${src}" .v)"
  out="${out_dir}/${stem}.json"
  echo "  -> yosys synth ${src}"
  yosys -p "read_verilog ${src}; synth -auto-top -flatten; write_json ${out}"
done < "${manifest}"
