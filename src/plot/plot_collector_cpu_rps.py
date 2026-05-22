#!/usr/bin/env python3
"""Plot collector resource usage and latency across request rates."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


SERIES = [
    ("pcap", "TraceFusion pcap", "#9CA3AF"),
    ("ebpf", "TraceFusion eBPF", "#4C72B0"),
    ("deepflow", "DeepFlow", "#55A868"),
]

METRICS = {
    "cpu": {
        "column": "collector_process_cpu_pct",
        "ylabel": "Collector CPU (%)",
        "suffix": "collector_cpu_rps",
        "value_offset": 0.8,
        "min_ymax": 10.0,
    },
    "memory": {
        "column": "collector_rss_peak_mb",
        "ylabel": "Peak Memory (MB)",
        "suffix": "collector_memory_rps",
        "value_offset": 6.0,
        "min_ymax": 80.0,
    },
    "latency_p50": {
        "column": "latency_p50_ms",
        "ylabel": "P50 Latency (ms)",
        "suffix": "collector_latency_p50_overhead_rps",
        "value_offset": 0.8,
        "min_ymax": 12.0,
    },
    "latency_p99": {
        "column": "latency_p99_ms",
        "ylabel": "P99 Latency (ms)",
        "suffix": "collector_latency_p99_overhead_rps",
        "value_offset": 0.8,
        "min_ymax": 20.0,
    },
}


def parse_float(value: str | None, *, field: str) -> float:
    if value is None or value == "":
        raise ValueError(f"empty metric value for {field}")
    return float(value)


def load_rows(
    summary_path: Path,
    metric_column: str,
    *,
    baseline_delta: bool = False,
) -> list[dict[str, float | str]]:
    grouped: dict[float, dict[str, dict[int, float]]] = defaultdict(lambda: defaultdict(dict))
    with summary_path.open(newline="") as f:
        for source_row in csv.DictReader(f):
            rate = parse_float(source_row.get("rate"), field="rate")
            mode = str(source_row.get("mode") or "")
            repeat = int(parse_float(source_row.get("repeat", "1"), field="repeat"))
            value = parse_float(
                source_row.get(metric_column),
                field=metric_column,
            )
            grouped[rate][mode][repeat] = value

    rows: list[dict[str, float | str]] = []
    for rate in sorted(grouped):
        row: dict[str, float | str] = {
            "rate": rate,
            "label": str(int(rate)) if rate.is_integer() else str(rate),
        }
        baseline_values = grouped[rate].get("baseline", {})
        baseline_mean = (
            sum(baseline_values.values()) / len(baseline_values)
            if baseline_values else 0.0
        )
        for mode, label, _color in SERIES:
            by_repeat = grouped[rate].get(mode, {})
            values = list(by_repeat.values())
            if baseline_delta:
                values = [
                    value - baseline_values.get(repeat, baseline_mean)
                    for repeat, value in sorted(by_repeat.items())
                ]
            row[label] = sum(values) / len(values) if values else 0.0
            row[f"{label}_std"] = statistics.stdev(values) if len(values) > 1 else 0.0
        rows.append(row)
    if not rows:
        raise RuntimeError(f"No data rows found in {summary_path}")
    return rows


def write_plot_csv(rows: list[dict[str, float | str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["rate", *[label for _mode, label, _color in SERIES]]
    fieldnames.extend(f"{label}_std" for _mode, label, _color in SERIES)
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "rate": row["label"],
                    **{label: row[label] for _mode, label, _color in SERIES},
                    **{f"{label}_std": row[f"{label}_std"] for _mode, label, _color in SERIES},
                }
            )


def configure_matplotlib():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

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
    return plt


def plot_metric(
    rows: list[dict[str, float | str]],
    *,
    ylabel: str,
    output_path: Path,
    pdf_output_path: Path | None,
    title: str,
    y_max: float | None,
    min_ymax: float,
    value_offset: float,
) -> None:
    import numpy as np

    group_spacing = 0.9
    x_values = np.arange(len(rows)) * group_spacing
    bar_width = 0.2
    hatches = ["", "//", "\\\\"]
    plt = configure_matplotlib()
    fig, ax = plt.subplots(figsize=(6.6, 4.2), dpi=300)

    max_value = 0.0
    min_value = 0.0
    for series_idx, (_mode, label, color) in enumerate(SERIES):
        values = [float(row[label]) for row in rows]
        errors = [float(row[f"{label}_std"]) for row in rows]
        max_value = max(max_value, max(values) if values else 0.0)
        min_value = min(min_value, min(values) if values else 0.0)
        offset = (series_idx - (len(SERIES) - 1) / 2.0) * bar_width
        bars = ax.bar(
            x_values + offset,
            values,
            yerr=errors,
            capsize=3.0,
            error_kw={"elinewidth": 0.9, "capthick": 0.9, "ecolor": "black"},
            width=bar_width,
            label=label,
            color=color,
            edgecolor="black",
            linewidth=0.5,
            hatch=hatches[series_idx],
        )
        for bar, value in zip(bars, values):
            label_y = value + value_offset if value >= 0 else value - value_offset
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                label_y,
                f"{value:.1f}",
                ha="center",
                va="bottom" if value >= 0 else "top",
                fontsize=9.5,
            )

    y_max = y_max if y_max is not None else max(min_ymax, max_value * 1.22)
    y_min = min(0.0, min_value * 1.25)
    ax.set_xlabel("Request Rate (RPS)", fontweight="bold")
    ax.set_ylabel(ylabel, fontweight="bold")
    ax.set_xticks(x_values)
    ax.set_xticklabels([str(row["label"]) for row in rows])
    ax.set_xlim(x_values[0] - 0.45, x_values[-1] + 0.45)
    ax.set_ylim(y_min, y_max)
    if title:
        ax.set_title(title, pad=8)
    ax.grid(axis="y", linestyle=":", linewidth=0.75, alpha=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", direction="out", length=4.0, width=1.0, pad=3.5)
    ax.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.18), frameon=False)
    fig.subplots_adjust(bottom=0.20, top=0.80, left=0.13, right=0.99)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, bbox_inches="tight")
    print(f"wrote {output_path}")

    if pdf_output_path:
        pdf_output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(pdf_output_path, bbox_inches="tight")
        print(f"wrote {pdf_output_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        default="result/cpu_overhead/collector_resource_rps_sweep_repeat3/summary.csv",
    )
    parser.add_argument(
        "--output-dir",
        default="result/cpu_overhead/collector_resource_rps_sweep_repeat3",
    )
    parser.add_argument(
        "--metric",
        choices=[*METRICS, "all"],
        default="all",
        help="Metric to plot. Defaults to all: cpu, memory, p50 latency, and p99 latency.",
    )
    parser.add_argument("--title", default="")
    parser.add_argument("--y-max", type=float, default=None)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    metrics = list(METRICS) if args.metric == "all" else [args.metric]
    for metric_name in metrics:
        metric = METRICS[metric_name]
        rows = load_rows(
            Path(args.summary),
            str(metric["column"]),
            baseline_delta=bool(metric.get("baseline_delta", False)),
        )
        suffix = str(metric["suffix"])
        csv_output = output_dir / f"{suffix}.csv"
        write_plot_csv(rows, csv_output)
        plot_metric(
            rows,
            ylabel=str(metric["ylabel"]),
            output_path=output_dir / f"{suffix}.png",
            pdf_output_path=output_dir / f"{suffix}.pdf",
            title=args.title,
            y_max=args.y_max if len(metrics) == 1 else None,
            min_ymax=float(metric["min_ymax"]),
            value_offset=float(metric["value_offset"]),
        )
        print(f"wrote {csv_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
