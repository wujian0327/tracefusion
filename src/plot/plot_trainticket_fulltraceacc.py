#!/usr/bin/env python3
"""Plot TrainTicket FullTraceAcc across selected RPS points."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


SERIES = [
    ("TraceFusion", "#4C72B0", "o"),
    ("TraceWeaver", "#F59E0B", "s"),
    ("DeepFlow", "#55A868", "^"),
]


def parse_float(value: str | None, field: str) -> float:
    if value is None or value == "":
        raise ValueError(f"empty value for {field}")
    return float(value)


def read_points(summary_path: Path, rps_values: list[int]) -> list[dict[str, float]]:
    with summary_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    by_rps = {int(parse_float(row.get("rate"), "rate")): row for row in rows}

    points: list[dict[str, float]] = []
    for rps in rps_values:
        if rps not in by_rps:
            raise RuntimeError(f"RPS {rps} not found in {summary_path}")
        row = by_rps[rps]
        points.append(
            {
                "rps": float(rps),
                "TraceFusion": parse_float(
                    row.get("lineage_full_accuracy_pct"),
                    "lineage_full_accuracy_pct",
                ),
                "TraceWeaver": 0.0,
                "DeepFlow": 0.0,
            }
        )
    return points


def write_plot_csv(points: list[dict[str, float]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["rps", *[name for name, _color, _marker in SERIES]])
        writer.writeheader()
        writer.writerows(points)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        default="result/trainticket/summary.csv",
    )
    parser.add_argument(
        "--output",
        default="result/trainticket/trainticket_rps5_20_fulltraceacc.png",
    )
    parser.add_argument(
        "--pdf-output",
        default="result/trainticket/trainticket_rps5_20_fulltraceacc.pdf",
    )
    parser.add_argument(
        "--csv-output",
        default="result/trainticket/trainticket_rps5_20_fulltraceacc.csv",
    )
    parser.add_argument("--rps", default="5,10,15,20", help="Comma-separated RPS points to plot.")
    parser.add_argument("--y-min", type=float, default=0.0)
    parser.add_argument("--y-max", type=float, default=105.0)
    args = parser.parse_args()

    rps_values = [int(value.strip()) for value in args.rps.split(",") if value.strip()]
    points = read_points(Path(args.summary), rps_values)
    write_plot_csv(points, Path(args.csv_output))

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
    x_values = np.arange(len(points)) * group_spacing
    bar_width = 0.2
    hatches = ["", "//", "\\\\"]
    fig, ax = plt.subplots(figsize=(6.6, 4.2), dpi=300)

    for series_idx, (series_name, color, _marker) in enumerate(SERIES):
        y_values = [point[series_name] for point in points]
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
    ax.set_xticklabels([str(int(point["rps"])) for point in points])
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

    print(f"wrote {args.csv_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
