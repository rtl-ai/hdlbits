#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/run_yosys_synth.sh [manifest]
#   manifest: path to file list (default: listfile/rtl.f)
#
# Runs a lightweight synthesis flow per HDL source using Yosys to ensure the
# design is structurally valid.

manifest="${1:-listfile/rtl.f}"
parallel_jobs="${PARALLEL_JOBS:-1}"

if [[ ! -f "${manifest}" ]]; then
  echo "Manifest not found: ${manifest}" >&2
  exit 1
fi

out_dir="build/synth"
report_dir="build/reports"
metrics_dir="build/metrics"
mkdir -p "${out_dir}" "${report_dir}" "${metrics_dir}"

tmp_dir="$(mktemp -d "${report_dir}/yosys_tmp.XXXXXX")"

declare -a sources=()
overall_rc=0
declare -a stat_files=()

run_one() {
  local src="$1"
  [[ -z "${src}" ]] && return 0
  local stem out log_file stat_log stat_json status start_ns end_ns duration_secs script
  stem="$(basename "${src}" .v)"
  out="${out_dir}/${stem}.json"
  log_file="${report_dir}/${stem}.yosys.log"
  stat_log="${report_dir}/${stem}.stat.log"
  stat_json="${report_dir}/${stem}.stat.json"
  echo "  -> yosys synth ${src}"
  start_ns=$(date +%s%N)
  script=$(printf 'read_verilog -sv "%s"; synth -auto-top -flatten; write_json "%s"' "${src}" "${out}")
  if yosys -q -l "${log_file}" -p "${script}"; then
    status="passed"
  else
    status="failed"
  fi

  if [[ "${status}" == "passed" ]]; then
    if yosys -q -l "${stat_log}" -p "$(printf 'read_json \"%s\"; stat -json' "${out}")"; then
      python3 -m tools.report_utils yosys-summary \
        --log "${stat_log}" \
        --output "${stat_json}" \
        --missing-ok
    else
      status="failed"
    fi
  fi
  end_ns=$(date +%s%N)
  duration_secs=$(awk -v s="${start_ns}" -v e="${end_ns}" 'BEGIN { printf "%.6f", (e - s)/1e9 }')

  cmd_display=$(printf 'yosys -q -p %q' "${script}")
  python3 -m tools.report_utils yosys-entry \
    --jsonl "${tmp_dir}/${stem}.jsonl" \
    --source "${src}" \
    --status "${status}" \
    --command "${cmd_display}" \
    --log-path "${log_file}" \
    --output-artifact "${out}" \
    --duration-secs "${duration_secs}"

  if [[ "${status}" != "passed" ]]; then
    return 1
  fi
  return 0
}

pids=()
if (( parallel_jobs > 1 )); then
  while IFS= read -r src; do
    [[ -z "${src}" ]] && continue
    run_one "${src}" &
    pids+=($!)
    if ((${#pids[@]} >= parallel_jobs)); then
      wait -n || overall_rc=1
      new_pids=()
      for pid in "${pids[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
          new_pids+=("${pid}")
        fi
      done
      pids=("${new_pids[@]}")
    fi
  done < "${manifest}"
  for pid in "${pids[@]}"; do
    wait "${pid}" || overall_rc=1
  done
else
  while IFS= read -r src; do
    [[ -z "${src}" ]] && continue
    if ! run_one "${src}"; then
      overall_rc=1
    fi
  done < "${manifest}"
fi

tmp_json="${report_dir}/yosys_runs.jsonl"
: > "${tmp_json}"
if ls "${tmp_dir}"/*.jsonl >/dev/null 2>&1; then
  cat "${tmp_dir}"/*.jsonl >> "${tmp_json}"
fi
python3 -m tools.report_utils jsonl-to-json \
  --input "${tmp_json}" \
  --output "${report_dir}/yosys_runs_report.json"

rm -rf "${tmp_dir}"

mapfile -t stat_files < <(find "${report_dir}" -maxdepth 1 -name '*.stat.json' -print)

if ((${#stat_files[@]} > 0)); then
  python3 -m tools.report_utils aggregate-yosys-stats \
    --inputs "${stat_files[@]}" \
    --output "${report_dir}/yosys_synth_summary.json"
else
  printf '[]' > "${report_dir}/yosys_synth_summary.json"
fi

python3 -m tools.metrics yosys \
  --report "${report_dir}/yosys_runs_report.json" \
  --stage "synth" \
  --output "${metrics_dir}/synth_metrics.json"

exit ${overall_rc}
