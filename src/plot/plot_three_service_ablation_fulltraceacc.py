#!/usr/bin/env python3
"""Plot cumulative FullTraceAcc ablations for Bookinfo, Hotel, and TrainTicket."""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path


SERVICE_ORDER = ["Bookinfo", "Hotel", "TrainTicket"]
VARIANT_ORDER = ["Time-only", "+ Iterative Context", "+ Fallback"]
COLORS = {
    "Bookinfo": "#4C72B0",
    "Hotel": "#55A868",
    "TrainTicket": "#F59E0B",
}
MARKERS = {
    "Bookinfo": "o",
    "Hotel": "s",
    "TrainTicket": "^",
}
LEGEND_LABELS = {
    "Bookinfo": "BookInfo",
    "Hotel": "Hotel",
    "TrainTicket": "TrainTicket",
}
DISPLAY_LABELS = {
    "Time-only": "Time-only",
    "+ Iterative Context": "+ Iterative Context",
    "+ Fallback": "+ Fallback",
}


def parse_float(value: str | None, field: str) -> float:
    if value is None or value == "":
        raise ValueError(f"empty value for {field}")
    return float(value)


def parse_order(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def read_points(
    summary_path: Path,
    services: list[str],
    variants: list[str],
) -> list[dict[str, float | str]]:
    with summary_path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    by_key = {
        (row["service_label"], row["label"]): row
        for row in rows
    }

    points: list[dict[str, float | str]] = []
    for service in services:
        for variant in variants:
            key = (service, variant)
            if key not in by_key:
                raise RuntimeError(f"{service!r} / {variant!r} not found in {summary_path}")
            row = by_key[key]
            points.append(
                {
                    "service": service,
                    "variant": variant,
                    "rps": row.get("rps", ""),
                    "full_trace_accuracy_pct": parse_float(
                        row.get("full_trace_accuracy_pct"),
                        "full_trace_accuracy_pct",
                    ),
                }
            )
    return points


def write_plot_csv(points: list[dict[str, float | str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["service", "variant", "rps", "full_trace_accuracy_pct"],
        )
        writer.writeheader()
        writer.writerows(points)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        default="result/ablation_three_services/summary.csv",
    )
    parser.add_argument(
        "--output",
        default="result/ablation_three_services/three_service_ablation_fulltraceacc.png",
    )
    parser.add_argument(
        "--pdf-output",
        default="result/ablation_three_services/three_service_ablation_fulltraceacc.pdf",
    )
    parser.add_argument(
        "--csv-output",
        default="result/ablation_three_services/three_service_ablation_fulltraceacc.csv",
    )
    parser.add_argument("--services", default=",".join(SERVICE_ORDER))
    parser.add_argument("--variants", default=",".join(VARIANT_ORDER))
    parser.add_argument("--y-min", type=float, default=0.0)
    parser.add_argument("--y-max", type=float, default=105.0)
    args = parser.parse_args()

    services = parse_order(args.services)
    variants = parse_order(args.variants)
    points = read_points(Path(args.summary), services, variants)
    write_plot_csv(points, Path(args.csv_output))

    os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

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

    value_by_key = {
        (str(point["service"]), str(point["variant"])): float(point["full_trace_accuracy_pct"])
        for point in points
    }
    rps_by_service = {
        str(point["service"]): str(point["rps"])
        for point in points
    }
    x_step = 0.8
    x_values = [idx * x_step for idx in range(len(variants))]

    fig, ax = plt.subplots(figsize=(5.6, 3.9), dpi=300)
    for service in services:
        y_values = [value_by_key[(service, variant)] for variant in variants]
        label = LEGEND_LABELS.get(service, service)
        ax.plot(
            x_values,
            y_values,
            label=label,
            color=COLORS.get(service, "#4C72B0"),
            marker=MARKERS.get(service, "o"),
            markersize=6.4,
            markeredgecolor="black",
            markeredgewidth=0.45,
            linewidth=2.1,
        )

    ax.set_ylabel("Accuracy (%)")
    ax.set_xticks(x_values)
    ax.set_xticklabels(
        [DISPLAY_LABELS.get(variant, variant) for variant in variants],
        rotation=0,
        ha="center",
    )
    ax.set_ylim(args.y_min, args.y_max)
    ax.set_xlim(min(x_values) - 0.18, max(x_values) + 0.18)
    ax.grid(axis="y", linestyle=":", linewidth=0.75, alpha=0.55)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", direction="out", length=4.0, width=1.0, pad=3.5)
    ax.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.18), frameon=False)
    fig.subplots_adjust(bottom=0.25, top=0.80, left=0.15, right=0.98)

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
