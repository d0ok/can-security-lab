#!/usr/bin/env python3
"""Generate the two summary plots referenced in the main README."""
import argparse
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, ".")
from analyze_can import load_log


def plot_bus_share(logfile, outdir):
    df = load_log(logfile)
    counts = df["can_id"].value_counts()
    labels = [f"0x{c:03X}" for c in counts.index]
    total = counts.sum()

    fig, ax = plt.subplots(figsize=(7, 5))
    colors = ["#d62728" if c == 0 else "#4C72B0" for c in counts.index]
    ax.bar(labels, counts.values, color=colors)
    ax.set_ylabel("Frame count")
    ax.set_title(f"Bus traffic share during DoS flood (total={total} frames)")
    for i, v in enumerate(counts.values):
        ax.text(i, v, f"{v/total*100:.1f}%", ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "dos_bus_share.png"), dpi=150)
    plt.close(fig)


def plot_packet_loss(marker_file, logfile, outdir):
    marker = json.load(open(marker_file))
    df = load_log(logfile)
    sent = marker["frames_sent"]
    captured = len(df[df["can_id"] == marker["target_id"]])
    loss_pct = (1 - captured / sent) * 100

    fig, ax = plt.subplots(figsize=(5, 5))
    ax.bar(["Sent by\nattacker", "Captured\nin log"], [sent, captured],
           color=["#d62728", "#4C72B0"])
    ax.set_ylabel("Frame count")
    ax.set_title(f"Flood ID 0x{marker['target_id']:03X}: "
                 f"{loss_pct:.0f}% frame loss in logging tool")
    for i, v in enumerate([sent, captured]):
        ax.text(i, v, f"{v:,}", ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "dos_packet_loss.png"), dpi=150)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dos-log", default="../../logs/dos_attack.log")
    ap.add_argument("--marker-file", default="../../logs/dos_marker.json")
    ap.add_argument("--outdir", default="../../docs/plots")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    plot_bus_share(args.dos_log, args.outdir)
    plot_packet_loss(args.marker_file, args.dos_log, args.outdir)
    print(f"Saved plots to {args.outdir}/")


if __name__ == "__main__":
    main()
