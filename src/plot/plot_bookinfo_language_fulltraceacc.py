#!/usr/bin/env python3
"""Plot Bookinfo FullTraceAcc by implementation language/framework."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


IMPLEMENTATIONS = [
    (
        "Go-Gin",
        "result/bookinfo_go/summary.csv",
    ),
    (
        "Java-Spring",
        "result/bookinfo_java/summary.csv",
    ),
    (
        "Python-Flask",
        "result/bookinfo_python/summary.csv",
    ),
    (
        "Rust-Axum",
        "result/bookinfo_rust/summary.csv",
    ),
]

SERIES = [
    ("TraceFusion", "lineage_accuracy_pct", "#4C72B0"),
    ("TraceWeaver", "traceweaver_full_accuracy_pct", "#F59E0B"),
    ("DeepFlow", "deepflow_full_accuracy_pct", "#55A868"),
]


def parse_float(value: str) -> float:
    if value is None or value == "":
        raise ValueError("empty metric value")
    return float(value)


def read_summary_row(path: Path) -> dict[str, str]:
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise RuntimeError(f"No data rows found in {path}")
    return rows[0]


def load_data(implementations: list[tuple[str, Path]]) -> list[dict[str, float | str]]:
    rows: list[dict[str, float | str]] = []
    for label, summary_path in implementations:
        source_row = read_summary_row(summary_path)
        row: dict[str, float | str] = {"implementation": label}
        for series_name, column, _color in SERIES:
            row[series_name] = parse_float(source_row[column])
        rows.append(row)
    return rows


def write_csv(rows: list[dict[str, float | str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["implementation", *[name for name, _column, _color in SERIES]])
        writer.writeheader()
        writer.writerows(rows)


def parse_implementation_arg(values: list[str] | None) -> list[tuple[str, Path]]:
    if not values:
        return [(label, Path(path)) for label, path in IMPLEMENTATIONS]

    implementations: list[tuple[str, Path]] = []
    for value in values:
        if "=" not in value:
            raise SystemExit(f"Invalid --implementation value {value!r}; expected Label=summary.csv")
        label, path = value.split("=", 1)
        label = label.strip()
        path = path.strip()
        if not label or not path:
            raise SystemExit(f"Invalid --implementation value {value!r}; expected Label=summary.csv")
        implementations.append((label, Path(path)))
    return implementations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--implementation",
        action="append",
        metavar="LABEL=SUMMARY",
        help="Implementation label and summary.csv path. May be repeated. Defaults to Go-Gin, Java-Spring, Python-Flask, Rust-Axum.",
    )
    parser.add_argument(
        "--output",
        default="result/bookinfo_language_fulltraceacc/bookinfo_language_fulltraceacc.png",
    )
    parser.add_argument(
        "--pdf-output",
        default="result/bookinfo_language_fulltraceacc/bookinfo_language_fulltraceacc.pdf",
    )
    parser.add_argument(
        "--csv-output",
        default="result/bookinfo_language_fulltraceacc/fulltraceacc.csv",
    )
    parser.add_argument("--title", default="")
    parser.add_argument("--y-max", type=float, default=105.0)
    args = parser.parse_args()

    implementations = parse_implementation_arg(args.implementation)
    rows = load_data(implementations)
    write_csv(rows, Path(args.csv_output))

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 16,
            "axes.labelsize": 14,
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
    width = 0.2
    hatches = ["", "//", "\\\\"]
    fig, ax = plt.subplots(figsize=(6.6, 4.2), dpi=300)

    for series_idx, (series_name, _column, color) in enumerate(SERIES):
        values = [float(row[series_name]) for row in rows]
        bars = ax.bar(
            x_values + (series_idx - 1) * width,
            values,
            width,
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

    ax.set_ylabel("Accuracy (%)")
    ax.set_xlabel("Language-Framework", fontweight="bold")
    ax.set_xticks(x_values)
    ax.set_xticklabels([str(row["implementation"]) for row in rows])
    ax.set_ylim(0, args.y_max)
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
