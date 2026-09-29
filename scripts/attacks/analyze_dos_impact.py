#!/usr/bin/env python3
"""
Analyze the impact of a DoS flood on a legitimate CAN ID, using the
precise flood start/end timestamps written by dos_attack.py's marker
file to define "before / during / after" windows (instead of guessing
from wall-clock observation, which is unreliable).
"""
import argparse
import json
import statistics as stats
import sys

sys.path.insert(0, "../common")
from analyze_can import load_log


def window_stats(times, lo, hi):
    in_window = sorted(t for t in times if lo <= t < hi)
    if len(in_window) < 2:
        return None
    deltas_ms = [(in_window[i] - in_window[i - 1]) * 1000
                 for i in range(1, len(in_window))]
    return {
        "frames": len(in_window),
        "span_s": in_window[-1] - in_window[0],
        "mean_ms": stats.mean(deltas_ms),
        "stdev_ms": stats.pstdev(deltas_ms),
        "max_ms": max(deltas_ms),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile")
    ap.add_argument("--marker-file", default="../../logs/dos_marker.json")
    ap.add_argument("--target-id", type=lambda x: int(x, 0), default=0x100,
                     help="legitimate ID to measure impact on")
    ap.add_argument("--margin-s", type=float, default=2.0,
                     help="seconds of buffer excluded around the flood edges, "
                          "to avoid mixing transition effects into before/after")
    args = ap.parse_args()

    marker = json.load(open(args.marker_file))
    df = load_log(args.logfile)

    # convert flood marker's unix time into the log's relative "time" axis
    log_start_unix = df["timestamp"].iloc[0]
    flood_start = marker["flood_start_unix"] - log_start_unix
    flood_end = marker["flood_end_unix"] - log_start_unix

    target = df[df["can_id"] == args.target_id]
    times = target["time"].tolist()

    before = window_stats(times, 0, flood_start - args.margin_s)
    during = window_stats(times, flood_start, flood_end)
    after = window_stats(times, flood_end + args.margin_s, df["time"].max())

    print(f"Flood window (log-relative): {flood_start:.2f}s - {flood_end:.2f}s "
          f"({flood_end - flood_start:.2f}s duration)")
    print(f"Target ID: 0x{args.target_id:03X}\n")

    for label, w in [("BEFORE", before), ("DURING", during), ("AFTER", after)]:
        if w is None:
            print(f"{label:8s} insufficient data")
            continue
        print(f"{label:8s} frames={w['frames']:5d}  span={w['span_s']:6.2f}s  "
              f"mean_period={w['mean_ms']:7.2f}ms  jitter(stdev)={w['stdev_ms']:7.2f}ms  "
              f"max_gap={w['max_ms']:8.2f}ms")

    if before and during:
        ratio = during["stdev_ms"] / before["stdev_ms"] if before["stdev_ms"] > 0 else float("inf")
        print(f"\nJitter increase during flood: {ratio:.1f}x baseline")


if __name__ == "__main__":
    main()
