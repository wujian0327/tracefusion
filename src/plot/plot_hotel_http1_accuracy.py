#!/usr/bin/env python3
"""Plot Hotel HTTP/1.1 accuracy across concurrency/load points."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


SERIES = [
    ("TraceFusion", "lineage_full_accuracy_pct", "#4C72B0", "o"),
    ("TraceWeaver", "traceweaver_full_accuracy_pct", "#F59E0B", "s"),
    ("DeepFlow", "deepflow_full_accuracy_pct", "#55A868", "^"),
]


def parse_float(value: str | None, *, field: str) -> float:
    if value is None or value == "":
        raise ValueError(f"empty metric value for {field}")
    return float(value)


def load_rows(summary_path: Path, x_column: str) -> list[dict[str, float | str]]:
    with summary_path.open(newline="") as f:
        source_rows = list(csv.DictReader(f))
    if not source_rows:
        raise RuntimeError(f"No data rows found in {summary_path}")

    rows: list[dict[str, float | str]] = []
    for source_row in source_rows:
        row: dict[str, float | str] = {
            "x": parse_float(source_row.get(x_column), field=x_column),
            "label": str(source_row.get(x_column) or ""),
        }
        for series_name, column, _color, _marker in SERIES:
            row[series_name] = parse_float(source_row.get(column), field=column)
        rows.append(row)
    return sorted(rows, key=lambda item: float(item["x"]))


def write_plot_csv(rows: list[dict[str, float | str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["concurrency", *[name for name, _column, _color, _marker in SERIES]]
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "concurrency": row["label"],
                    **{name: row[name] for name, _column, _color, _marker in SERIES},
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        default="result/hotel_http1/summary.csv",
        help="Hotel HTTP/1.1 sweep summary.csv.",
    )
    parser.add_argument(
        "--x-column",
        default="rate",
        help="Column used for x-axis ticks. Defaults to rate for the fixed-c=20 sweep.",
    )
    parser.add_argument(
        "--x-label",
        default="Request Rate (RPS)",
    )
    parser.add_argument(
        "--output",
        default="result/hotel_http1/hotel_http1_fulltraceacc_rps.png",
    )
    parser.add_argument(
        "--pdf-output",
        default="result/hotel_http1/hotel_http1_fulltraceacc_rps.pdf",
    )
    parser.add_argument(
        "--csv-output",
        default="result/hotel_http1/hotel_http1_fulltraceacc_rps.csv",
    )
    parser.add_argument("--title", default="")
    parser.add_argument("--y-min", type=float, default=0.0)
    parser.add_argument("--y-max", type=float, default=105.0)
    args = parser.parse_args()

    rows = load_rows(Path(args.summary), args.x_column)
    write_plot_csv(rows, Path(args.csv_output))

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

    for series_idx, (series_name, _column, color, _marker) in enumerate(SERIES):
        values = [float(row[series_name]) for row in rows]
        offset = (series_idx - (len(SERIES) - 1) / 2.0) * bar_width
        bars = ax.bar(
            x_values + offset,
            values,
            width=bar_width,
            label=series_name,
            color=color,
            edgecolor="black",
            linewidth=0.5,
            hatch=hatches[series_idx],
        )
        for bar, value in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                value + 0.8,
                f"{value:.1f}",
                ha="center",
                va="bottom",
                fontsize=9.5,
            )

    ax.set_xlabel(args.x_label, fontweight="bold")
    ax.set_ylabel("Accuracy (%)")
    ax.set_xticks(x_values)
    ax.set_xticklabels([str(row["label"]) for row in rows])
    ax.set_xlim(x_values[0] - 0.45, x_values[-1] + 0.45)
    ax.set_ylim(args.y_min, args.y_max)
    if args.title:
        ax.set_title(args.title, pad=8)
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

    if args.csv_output:
        print(f"wrote {args.csv_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
