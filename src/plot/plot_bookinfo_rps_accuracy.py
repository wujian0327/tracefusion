#!/usr/bin/env python3
"""Plot Bookinfo FullTraceAcc across request rates from summary.csv."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


SERIES = [
    ("TraceFusion", "lineage_accuracy_pct", "#4C72B0", "o"),
    ("TraceWeaver", "traceweaver_full_accuracy_pct", "#F59E0B", "s"),
    ("DeepFlow", "deepflow_full_accuracy_pct", "#55A868", "^"),
]

TABLE_COLUMNS = [
    ("FullTraceAcc", {
        "TraceFusion": "lineage_accuracy_pct",
        "TraceWeaver": "traceweaver_full_accuracy_pct",
        "DeepFlow": "deepflow_full_accuracy_pct",
    }),
    ("TraceAssign", {
        "TraceFusion": "lineage_trace_assignment_accuracy_pct",
        "TraceWeaver": "traceweaver_trace_assignment_accuracy_pct",
        "DeepFlow": "deepflow_trace_assignment_accuracy_pct",
    }),
    ("SpanAcc", {
        "TraceFusion": "lineage_span_accuracy_pct",
        "TraceWeaver": "traceweaver_span_accuracy_pct",
        "DeepFlow": "deepflow_span_accuracy_pct",
    }),
    ("Coverage", {
        "TraceFusion": "lineage_coverage_pct",
        "TraceWeaver": "traceweaver_coverage_pct",
        "DeepFlow": "deepflow_coverage_pct",
    }),
    ("ParentEdge F1", {
        "TraceFusion": "lineage_parent_child_edge_f1_pct",
        "TraceWeaver": "traceweaver_parent_child_edge_f1_pct",
        "DeepFlow": "deepflow_parent_child_edge_f1_pct",
    }),
]


def parse_float(value: str | None, field: str) -> float:
    if value is None or value == "":
        raise ValueError(f"empty value for {field}")
    return float(value)


def read_summary(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise RuntimeError(f"No rows found in {path}")
    return sorted(rows, key=lambda row: parse_float(row.get("rate"), "rate"))


def fmt_pct(value: str | float) -> str:
    return f"{float(value):.2f}%"


def write_fulltrace_csv(rows: list[dict[str, str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["rps", *[name for name, _column, _color, _marker in SERIES]])
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "rps": row["rate"],
                    **{name: row[column] for name, column, _color, _marker in SERIES},
                }
            )


def write_metric_table(rows: list[dict[str, str]], csv_path: Path, md_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["RPS", "Baseline", *[name for name, _mapping in TABLE_COLUMNS]]
    table_rows: list[dict[str, str]] = []
    for row in rows:
        for baseline in ("TraceFusion", "TraceWeaver", "DeepFlow"):
            table_rows.append(
                {
                    "RPS": row["rate"],
                    "Baseline": baseline,
                    **{
                        metric_name: fmt_pct(row[mapping[baseline]])
                        for metric_name, mapping in TABLE_COLUMNS
                    },
                }
            )

    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(table_rows)

    lines = [
        "| " + " | ".join(fieldnames) + " |",
        "| " + " | ".join(["---:"] + ["---", *["---:" for _ in TABLE_COLUMNS]]) + " |",
    ]
    for table_row in table_rows:
        lines.append("| " + " | ".join(table_row[field] for field in fieldnames) + " |")
    md_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        default="result/bookinfo/summary.csv",
    )
    parser.add_argument(
        "--output",
        default="result/bookinfo/bookinfo_fulltraceacc_rps.png",
    )
    parser.add_argument(
        "--pdf-output",
        default="result/bookinfo/bookinfo_fulltraceacc_rps.pdf",
    )
    parser.add_argument(
        "--plot-csv-output",
        default="result/bookinfo/bookinfo_fulltraceacc_rps.csv",
    )
    parser.add_argument(
        "--table-csv-output",
        default="result/bookinfo/bookinfo_metrics_table.csv",
    )
    parser.add_argument(
        "--table-md-output",
        default="result/bookinfo/bookinfo_metrics_table.md",
    )
    parser.add_argument("--y-min", type=float, default=0.0)
    parser.add_argument("--y-max", type=float, default=105.0)
    args = parser.parse_args()

    rows = read_summary(Path(args.summary))
    write_fulltrace_csv(rows, Path(args.plot_csv_output))
    write_metric_table(rows, Path(args.table_csv_output), Path(args.table_md_output))

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 16,
            "axes.labelsize": 16,
            "axes.titlesize": 16,
            "xtick.labelsize": 16,
            "ytick.labelsize": 16,
            "legend.fontsize": 13,
            "axes.linewidth": 1.0,
            "legend.handlelength": 1.4,
            "legend.handletextpad": 0.45,
            "legend.columnspacing": 0.95,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )

    group_spacing = 0.9
    x_values = np.arange(len(rows)) * group_spacing
    bar_width = 0.2
    hatches = ["", "//", "\\\\"]
    fig, ax = plt.subplots(figsize=(6.6, 4.2), dpi=300)

    for series_idx, (series_name, column, color, _marker) in enumerate(SERIES):
        y_values = [parse_float(row[column], column) for row in rows]
        offset = (series_idx - (len(SERIES) - 1) / 2.0) * bar_width
        bars = ax.bar(
            x_values + offset,
            y_values,
            width=bar_width,
            label=series_name,
            color=color,
            edgecolor="black",
            linewidth=0.5,
            hatch=hatches[series_idx],
        )
        for bar, value in zip(bars, y_values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                value + 0.8,
                f"{value:.1f}",
                ha="center",
                va="bottom",
                fontsize=9.5,
            )

    ax.set_xlabel("Request Rate (RPS)", fontweight="bold")
    ax.set_ylabel("Accuracy (%)")
    ax.set_xticks(x_values)
    ax.set_xticklabels([str(int(parse_float(row["rate"], "rate"))) for row in rows])
    ax.set_xlim(x_values[0] - 0.45, x_values[-1] + 0.45)
    ax.set_ylim(args.y_min, args.y_max)
    ax.grid(axis="y", linestyle=":", linewidth=0.75, alpha=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", direction="out", length=4.0, width=1.0, pad=3.5)
    ax.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.18), frameon=False)
    fig.subplots_adjust(bottom=0.20, top=0.80, left=0.13, right=0.99)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, bbox_inches="tight")
    print(f"wrote {output_path}")

    if args.pdf_output:
        pdf_output_path = Path(args.pdf_output)
        pdf_output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(pdf_output_path, bbox_inches="tight")
        print(f"wrote {pdf_output_path}")

    print(f"wrote {args.plot_csv_output}")
    print(f"wrote {args.table_csv_output}")
    print(f"wrote {args.table_md_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
