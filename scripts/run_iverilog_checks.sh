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
    ;;
  elaborate)
    echo "Running iverilog elaboration checks using ${manifest}"
    ;;
  *)
    echo "Unsupported mode: ${mode}" >&2
    exit 1
    ;;
esac

report_dir="build/reports"
deps_dir="build/deps"
metrics_dir="build/metrics"
mkdir -p "${report_dir}" "${deps_dir}" "${metrics_dir}"

tmp_json="${report_dir}/iverilog_${mode}_runs.jsonl"
: > "${tmp_json}"

overall_rc=0

while IFS= read -r src; do
  [[ -z "${src}" ]] && continue
  stem="$(basename "${src}" .v)"
  dep_file="${deps_dir}/${stem}.${mode}.d"
  log_file="${report_dir}/${stem}.${mode}.log"
  out=""
  printf '  -> iverilog (%s) %s\n' "${mode}" "${src}"

  if [[ "${mode}" == "compile" ]]; then
    cmd=(iverilog -g2012 -tnull -M "${dep_file}" -o /dev/null "${src}")
  else
    build_dir="build/elab"
    mkdir -p "${build_dir}"
    out="${build_dir}/${stem}.vvp"
    cmd=(iverilog -g2012 -M "${dep_file}" -o "${out}" "${src}")
  fi

  if "${cmd[@]}" >"${log_file}" 2>&1; then
    status="passed"
  else
    status="failed"
    overall_rc=1
  fi

  cmd_display=$(printf '%q ' "${cmd[@]}")
  export SRC="${src}"
  export MODE="${mode}"
  export STATUS="${status}"
  export CMD="${cmd_display}"
  export LOG_FILE="${log_file}"
  export DEP_FILE="${dep_file}"
  export OUTPUT_PATH="${out:-}"

  python3 -m tools.report_utils iverilog-entry \
    --jsonl "${tmp_json}" \
    --source "${src}" \
    --mode "${mode}" \
    --status "${status}" \
    --command "${cmd_display}" \
    --log-path "${log_file}" \
    --dep-path "${dep_file}" \
    ${out:+--output-artifact "${out}"}
done < "${manifest}"

python3 -m tools.report_utils jsonl-to-json \
  --input "${tmp_json}" \
  --output "${report_dir}/iverilog_${mode}_report.json"

rm -f "${tmp_json}"

mkdir -p "${metrics_dir}"
python3 -m tools.metrics iverilog \
  --report "${report_dir}/iverilog_${mode}_report.json" \
  --stage "${mode}" \
  --output "${metrics_dir}/${mode}_metrics.json"

exit ${overall_rc}
