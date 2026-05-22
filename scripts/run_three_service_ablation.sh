#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BOOKINFO_CSV="${BOOKINFO_CSV:-$ROOT_DIR/result/bookinfo/conn_20_rps_400/cleaned_data.csv}"
HOTEL_CSV="${HOTEL_CSV:-$ROOT_DIR/result/hotel_http1/conn_50_rps_1400/cleaned_data.csv}"
TRAINTICKET_RPS="${TRAINTICKET_RPS:-7}"
TRAINTICKET_CSV="${TRAINTICKET_CSV:-$ROOT_DIR/result/trainticket/conn_2_rps_${TRAINTICKET_RPS}/cleaned_data.csv}"

OUT_DIR="${OUT_DIR:-$ROOT_DIR/result/ablation_three_services}"
SUMMARY_CSV="${SUMMARY_CSV:-$OUT_DIR/summary.csv}"
TRACEFUSION="${TRACEFUSION:-$ROOT_DIR/src/tracefusion.py}"
PLOT="${PLOT:-1}"
REUSE_REPORTS="${REUSE_REPORTS:-1}"
TRAINTICKET_FULL_SLOT_FALLBACK="${TRAINTICKET_FULL_SLOT_FALLBACK:-1}"
TRAINTICKET_FULL_CONTAINMENT_FALLBACK="${TRAINTICKET_FULL_CONTAINMENT_FALLBACK:-1}"
TRAINTICKET_FULL_UNSUPERVISED_GATE="${TRAINTICKET_FULL_UNSUPERVISED_GATE:-1}"
TRAINTICKET_FULL_SLOT_LOW_DIVERSITY_RATIO="${TRAINTICKET_FULL_SLOT_LOW_DIVERSITY_RATIO:-0.3333333333333333}"
TRAINTICKET_FULL_SLOT_LOW_SIGNAL="${TRAINTICKET_FULL_SLOT_LOW_SIGNAL:-0.7845594221512074}"
TRAINTICKET_FULL_SLOT_MAX_P95_MS="${TRAINTICKET_FULL_SLOT_MAX_P95_MS:-180}"
TRAINTICKET_FULL_SLOT_WEAK_SIGNAL_MAX_P95_MS="${TRAINTICKET_FULL_SLOT_WEAK_SIGNAL_MAX_P95_MS:-220}"
TRAINTICKET_FULL_SLOT_ROOT_REPEATED_MAX_P95_MS="${TRAINTICKET_FULL_SLOT_ROOT_REPEATED_MAX_P95_MS:-180}"
TRAINTICKET_FULL_CONTAINMENT_LOW_DIVERSITY_RATIO="${TRAINTICKET_FULL_CONTAINMENT_LOW_DIVERSITY_RATIO:-0.3333333333333333}"
TRAINTICKET_FULL_CONTAINMENT_MAX_OUTSIDE_MS="${TRAINTICKET_FULL_CONTAINMENT_MAX_OUTSIDE_MS:-160}"
BOOKINFO_ABLATION_DIR="${BOOKINFO_ABLATION_DIR:-$OUT_DIR/bookinfo}"
HOTEL_ABLATION_DIR="${HOTEL_ABLATION_DIR:-$OUT_DIR/hotel}"
TRAINTICKET_ABLATION_DIR="${TRAINTICKET_ABLATION_DIR:-$ROOT_DIR/result/trainticket/ablation_rps${TRAINTICKET_RPS}}"

log() {
  printf '[%(%Y-%m-%d %H:%M:%S)T] %s\n' -1 "$*"
}

require_csv() {
  local label="$1"
  local path="$2"
  if [[ ! -f "$path" ]]; then
    cat >&2 <<EOF
$label cleaned CSV not found:
  $path

Override the default with ${label^^}_CSV=/path/to/cleaned_data.csv.
EOF
    exit 1
  fi
}

require_csv "bookinfo" "$BOOKINFO_CSV"
require_csv "hotel" "$HOTEL_CSV"
require_csv "trainticket" "$TRAINTICKET_CSV"

mkdir -p "$OUT_DIR"
printf 'service,service_label,rps,variant,label,full_trace_accuracy_pct,full_trace_correct,full_trace_total,trace_assignment_accuracy_pct,span_accuracy_pct,parent_child_edge_f1_pct,root_direct_accuracy_pct,report_path\n' > "$SUMMARY_CSV"

append_summary_row() {
  local service="$1"
  local service_label="$2"
  local rps="$3"
  local variant="$4"
  local label="$5"
  local report_path="$6"
  python3 - "$service" "$service_label" "$rps" "$variant" "$label" "$report_path" "$SUMMARY_CSV" <<'PY'
import csv
import json
import sys
from pathlib import Path

service, service_label, rps, variant, label, report_path, summary_path = sys.argv[1:8]
report = json.loads(Path(report_path).read_text())

def first(*keys, default=""):
    for key in keys:
        value = report.get(key)
        if value not in (None, ""):
            return value
    return default

row = {
    "service": service,
    "service_label": service_label,
    "rps": rps,
    "variant": variant,
    "label": label,
    "full_trace_accuracy_pct": first("full_trace_accuracy_pct", "accuracy_pct", default=0.0),
    "full_trace_correct": first("full_trace_accuracy_ok", "accuracy_ok", default=0),
    "full_trace_total": first("full_trace_accuracy_total", "root_trace_count", default=0),
    "trace_assignment_accuracy_pct": first("trace_assignment_accuracy_pct", default=""),
    "span_accuracy_pct": first("span_accuracy_pct", "edge_accuracy_pct", default=""),
    "parent_child_edge_f1_pct": first("parent_child_edge_f1_pct", default=""),
    "root_direct_accuracy_pct": first("root_direct_accuracy_pct", default=""),
    "report_path": report_path,
}

with Path(summary_path).open("a", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(row))
    writer.writerow(row)
PY
}

run_variant() {
  local service="$1"
  local service_label="$2"
  local rps="$3"
  local csv_path="$4"
  local variant="$5"
  local label="$6"
  shift 6

  local service_dir="$OUT_DIR/$service"
  if [[ "$service" == "bookinfo" ]]; then
    service_dir="$BOOKINFO_ABLATION_DIR"
  elif [[ "$service" == "hotel" ]]; then
    service_dir="$HOTEL_ABLATION_DIR"
  elif [[ "$service" == "trainticket" ]]; then
    service_dir="$TRAINTICKET_ABLATION_DIR"
  fi
  local report_path="$service_dir/${variant}.json"
  local log_path="$service_dir/${variant}.log"
  mkdir -p "$service_dir"

  if [[ "$REUSE_REPORTS" == "1" && -f "$report_path" ]]; then
    if python3 - "$report_path" "$csv_path" <<'PY'
import json
import sys
from pathlib import Path

report_path, csv_path = sys.argv[1:3]
try:
    report = json.loads(Path(report_path).read_text())
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if report.get("csv_path") == csv_path else 1)
PY
    then
      log "reusing $service_label RPS=$rps ablation: $label"
      append_summary_row "$service" "$service_label" "$rps" "$variant" "$label" "$report_path"
      return 0
    fi
  fi

  log "running $service_label RPS=$rps ablation: $label"
  (
    cd "$ROOT_DIR"
    env "$@" python3 "$TRACEFUSION" \
      --csv-path "$csv_path" \
      --json-out "$report_path"
  ) >"$log_path" 2>&1
  append_summary_row "$service" "$service_label" "$rps" "$variant" "$label" "$report_path"
}

run_service() {
  local service="$1"
  local service_label="$2"
  local rps="$3"
  local csv_path="$4"

  run_variant "$service" "$service_label" "$rps" "$csv_path" "time_only" "Time-only" \
    LINEAGE_GRAPH_CONTEXT_MODE=static \
    LINEAGE_GRAPH_DATA_WEIGHT=0 \
    LINEAGE_GRAPH_TRACE_CONTEXT_WEIGHT=0 \
    LINEAGE_GRAPH_SLOT_FALLBACK=0 \
    LINEAGE_GRAPH_CONTAINMENT_FALLBACK=0 \
    LINEAGE_GRAPH_UNSUPERVISED_GATE=0 \
    LINEAGE_GRAPH_PARENT_RECONSTRUCTION=causal

  run_variant "$service" "$service_label" "$rps" "$csv_path" "iterative_context" "+ Iterative Context" \
    LINEAGE_GRAPH_CONTEXT_MODE=iterative \
    LINEAGE_GRAPH_DATA_WEIGHT=0 \
    LINEAGE_GRAPH_TRACE_CONTEXT_WEIGHT=40 \
    LINEAGE_GRAPH_SLOT_FALLBACK=0 \
    LINEAGE_GRAPH_CONTAINMENT_FALLBACK=0 \
    LINEAGE_GRAPH_UNSUPERVISED_GATE=0 \
    LINEAGE_GRAPH_PARENT_RECONSTRUCTION=causal

  if [[ "$service" == "trainticket" ]]; then
    run_variant "$service" "$service_label" "$rps" "$csv_path" "tracefusion" "+ Fallback" \
      LINEAGE_GRAPH_CONTEXT_MODE=iterative \
      LINEAGE_GRAPH_DATA_WEIGHT=20 \
      LINEAGE_GRAPH_TRACE_CONTEXT_WEIGHT=40 \
      LINEAGE_GRAPH_SLOT_FALLBACK="$TRAINTICKET_FULL_SLOT_FALLBACK" \
      LINEAGE_GRAPH_CONTAINMENT_FALLBACK="$TRAINTICKET_FULL_CONTAINMENT_FALLBACK" \
      LINEAGE_GRAPH_UNSUPERVISED_GATE="$TRAINTICKET_FULL_UNSUPERVISED_GATE" \
      LINEAGE_GRAPH_SLOT_LOW_DIVERSITY_RATIO="$TRAINTICKET_FULL_SLOT_LOW_DIVERSITY_RATIO" \
      LINEAGE_GRAPH_SLOT_LOW_SIGNAL="$TRAINTICKET_FULL_SLOT_LOW_SIGNAL" \
      LINEAGE_GRAPH_SLOT_MAX_P95_MS="$TRAINTICKET_FULL_SLOT_MAX_P95_MS" \
      LINEAGE_GRAPH_SLOT_WEAK_SIGNAL_MAX_P95_MS="$TRAINTICKET_FULL_SLOT_WEAK_SIGNAL_MAX_P95_MS" \
      LINEAGE_GRAPH_SLOT_ROOT_REPEATED_MAX_P95_MS="$TRAINTICKET_FULL_SLOT_ROOT_REPEATED_MAX_P95_MS" \
      LINEAGE_GRAPH_CONTAINMENT_LOW_DIVERSITY_RATIO="$TRAINTICKET_FULL_CONTAINMENT_LOW_DIVERSITY_RATIO" \
      LINEAGE_GRAPH_CONTAINMENT_MAX_OUTSIDE_MS="$TRAINTICKET_FULL_CONTAINMENT_MAX_OUTSIDE_MS" \
      LINEAGE_GRAPH_PARENT_RECONSTRUCTION=causal
  else
    run_variant "$service" "$service_label" "$rps" "$csv_path" "tracefusion" "+ Fallback" \
      LINEAGE_GRAPH_CONTEXT_MODE=iterative \
      LINEAGE_GRAPH_DATA_WEIGHT=20 \
      LINEAGE_GRAPH_TRACE_CONTEXT_WEIGHT=40 \
      LINEAGE_GRAPH_SLOT_FALLBACK=0 \
      LINEAGE_GRAPH_CONTAINMENT_FALLBACK=0 \
      LINEAGE_GRAPH_UNSUPERVISED_GATE=0 \
      LINEAGE_GRAPH_PARENT_RECONSTRUCTION=causal
  fi
}

run_service "bookinfo" "Bookinfo" "400" "$BOOKINFO_CSV"
run_service "hotel" "Hotel" "1400" "$HOTEL_CSV"
run_service "trainticket" "TrainTicket" "$TRAINTICKET_RPS" "$TRAINTICKET_CSV"

if [[ "$PLOT" == "1" ]]; then
  python3 "$ROOT_DIR/src/plot/plot_three_service_ablation_fulltraceacc.py" \
    --summary "$SUMMARY_CSV" \
    --output "$OUT_DIR/three_service_ablation_fulltraceacc.png" \
    --pdf-output "$OUT_DIR/three_service_ablation_fulltraceacc.pdf" \
    --csv-output "$OUT_DIR/three_service_ablation_fulltraceacc.csv"
fi

log "summary csv: $SUMMARY_CSV"
