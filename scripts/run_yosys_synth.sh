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
report_dir="build/reports"
mkdir -p "${out_dir}" "${report_dir}"

tmp_json="${report_dir}/yosys_runs.jsonl"
: > "${tmp_json}"

declare -a sources=()
overall_rc=0
declare -a stat_files=()

while IFS= read -r src; do
  [[ -z "${src}" ]] && continue
  sources+=("${src}")
  stem="$(basename "${src}" .v)"
  out="${out_dir}/${stem}.json"
  log_file="${report_dir}/${stem}.yosys.log"
  stat_log="${report_dir}/${stem}.stat.log"
  stat_json="${report_dir}/${stem}.stat.json"
  echo "  -> yosys synth ${src}"
  script=$(printf 'read_verilog -sv "%s"; synth -auto-top -flatten; write_json "%s"' "${src}" "${out}")
  if yosys -q -l "${log_file}" -p "${script}"; then
    status="passed"
  else
    status="failed"
    overall_rc=1
  fi

  if [[ "${status}" == "passed" ]]; then
    if yosys -q -l "${stat_log}" -p "$(printf 'read_json \"%s\"; stat -json' "${out}")"; then
      python3 -m tools.report_utils yosys-summary \
        --log "${stat_log}" \
        --output "${stat_json}" \
        --missing-ok
      stat_files+=("${stat_json}")
    else
      overall_rc=1
    fi
  fi

  cmd_display=$(printf 'yosys -q -p %q' "${script}")
  export SRC="${src}"
  export STATUS="${status}"
  export CMD="${cmd_display}"
  export LOG_FILE="${log_file}"
  export OUTPUT_JSON="${out}"

  python3 -m tools.report_utils yosys-entry \
    --jsonl "${tmp_json}" \
    --source "${src}" \
    --status "${status}" \
    --command "${cmd_display}" \
    --log-path "${log_file}" \
    --output-artifact "${out}"
done < "${manifest}"

python3 -m tools.report_utils jsonl-to-json \
  --input "${tmp_json}" \
  --output "${report_dir}/yosys_runs_report.json"

rm -f "${tmp_json}"

if ((${#stat_files[@]} > 0)); then
  python3 -m tools.report_utils aggregate-yosys-stats \
    --inputs "${stat_files[@]}" \
    --output "${report_dir}/yosys_synth_summary.json"
else
  printf '[]' > "${report_dir}/yosys_synth_summary.json"
fi

exit ${overall_rc}
