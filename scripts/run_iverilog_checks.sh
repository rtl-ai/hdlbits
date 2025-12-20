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
parallel_jobs="${PARALLEL_JOBS:-1}"

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
cache_dir="build/cache"
mkdir -p "${report_dir}" "${deps_dir}" "${metrics_dir}" "${cache_dir}"

cache_file="${cache_dir}/iverilog_${mode}_hashes.txt"
cache_lock="${cache_file}.lock"
touch "${cache_file}"
touch "${cache_lock}"

tmp_dir="$(mktemp -d "${report_dir}/iverilog_${mode}_tmp.XXXXXX")"

overall_rc=0

run_one() {
  local src="$1"
  [[ -z "${src}" ]] && return 0
  local stem dep_file log_file out cmd status start_ns end_ns duration_secs src_hash prev_hash
  stem="$(basename "${src}" .v)"
  dep_file="${deps_dir}/${stem}.${mode}.d"
  log_file="${report_dir}/${stem}.${mode}.log"
  out=""
  printf '  -> iverilog (%s) %s\n' "${mode}" "${src}"

  src_hash="$(sha256sum "${src}" | awk '{print $1}')"
  prev_hash=""
  if [[ "${IVERILOG_FORCE_FULL:-0}" != "1" ]]; then
    exec 200<>"${cache_lock}"
    flock -s 200
    prev_hash="$(grep -F " ${src}$" "${cache_file}" | awk '{print $1}' || true)"
    flock -u 200
    exec 200>&-
  fi

  if [[ "${mode}" == "compile" ]]; then
    cmd=(iverilog -g2012 -tnull -M "${dep_file}" -o /dev/null "${src}")
  else
    build_dir="build/elab"
    mkdir -p "${build_dir}"
    out="${build_dir}/${stem}.vvp"
    cmd=(iverilog -g2012 -M "${dep_file}" -o "${out}" "${src}")
  fi

  start_ns=$(date +%s%N)
  duration_secs=0
  if [[ "${src_hash}" == "${prev_hash}" ]]; then
    status="skipped"
    : > "${log_file}"
  else
    if "${cmd[@]}" >"${log_file}" 2>&1; then
      status="passed"
    else
      status="failed"
    fi
    end_ns=$(date +%s%N)
    duration_secs=$(awk -v s="${start_ns}" -v e="${end_ns}" 'BEGIN { printf "%.6f", (e - s)/1e9 }')
    if [[ "${IVERILOG_FORCE_FULL:-0}" != "1" ]]; then
      exec 200<>"${cache_lock}"
      flock -x 200
      grep -vF " ${src}$" "${cache_file}" > "${cache_file}.tmp" || true
      mv "${cache_file}.tmp" "${cache_file}"
      echo "${src_hash} ${src}" >> "${cache_file}"
      flock -u 200
      exec 200>&-
    fi
  fi

  cmd_display=$(printf '%q ' "${cmd[@]}")
  python3 -m tools.report_utils iverilog-entry \
    --jsonl "${tmp_dir}/${stem}.jsonl" \
    --source "${src}" \
    --mode "${mode}" \
    --status "${status}" \
    --command "${cmd_display}" \
    --log-path "${log_file}" \
    --dep-path "${dep_file}" \
    ${out:+--output-artifact "${out}"} \
    --duration-secs "${duration_secs}"
}

pids=()
if (( parallel_jobs > 1 )); then
  while IFS= read -r src; do
    [[ -z "${src}" ]] && continue
    run_one "${src}" &
    pids+=($!)
    if ((${#pids[@]} >= parallel_jobs)); then
      wait -n || overall_rc=1
      # remove finished pids
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

tmp_json="${report_dir}/iverilog_${mode}_runs.jsonl"
: > "${tmp_json}"
if ls "${tmp_dir}"/*.jsonl >/dev/null 2>&1; then
  cat "${tmp_dir}"/*.jsonl >> "${tmp_json}"
fi

python3 -m tools.report_utils jsonl-to-json \
  --input "${tmp_json}" \
  --output "${report_dir}/iverilog_${mode}_report.json"

rm -rf "${tmp_dir}"

mkdir -p "${metrics_dir}"
python3 -m tools.metrics iverilog \
  --report "${report_dir}/iverilog_${mode}_report.json" \
  --stage "${mode}" \
  --output "${metrics_dir}/${mode}_metrics.json"

exit ${overall_rc}
