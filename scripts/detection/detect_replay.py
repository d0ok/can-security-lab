#!/usr/bin/env python3
"""
Replay / burst detector (per-ID rate anomaly).

Rationale: payload-repeat streaks are NOT a reliable replay signature,
because slow-changing signals (e.g. an 8-bit speed value near a sine
peak) naturally repeat the same payload for many consecutive frames.
The reliable signature of a replay or burst injection is instead an
ID's *frame arrival rate* exceeding its own established normal rate,
regardless of what the payload contains.

Method: bin each ID's frames into fixed-size time windows, compare each
window's frame count to that ID's median (baseline) count per window.
Flag windows that exceed the baseline by a configurable multiplier.
"""
import argparse
import sys
sys.path.insert(0, "../common")
from analyze_can import load_log


def detect(df, window_s, multiplier, min_extra):
    alerts = []
    max_t = df["time"].max()
    n_bins = int(max_t // window_s) + 1

    for can_id, g in df.groupby("can_id"):
        bin_idx = (g["time"] // window_s).astype(int)
        counts = bin_idx.value_counts().reindex(range(n_bins), fill_value=0).sort_index()

        baseline = counts.median()
        if baseline == 0:
            continue

        for b, count in counts.items():
            if count > baseline * multiplier and (count - baseline) >= min_extra:
                alerts.append({
                    "window_start": round(b * window_s, 2),
                    "window_end": round((b + 1) * window_s, 2),
                    "id": f"0x{can_id:03X}",
                    "count": int(count),
                    "baseline": baseline,
                })
    return sorted(alerts, key=lambda a: a["window_start"])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile")
    ap.add_argument("--window-s", type=float, default=1.0,
                     help="time window size in seconds")
    ap.add_argument("--multiplier", type=float, default=2.0,
                     help="flag windows with count > multiplier * baseline")
    ap.add_argument("--min-extra", type=float, default=3,
                     help="require at least this many frames above baseline")
    args = ap.parse_args()

    df = load_log(args.logfile)
    alerts = detect(df, args.window_s, args.multiplier, args.min_extra)

    if not alerts:
        print("No rate anomalies found.")
        return

    print(f"{len(alerts)} anomalous window(s):\n")
    for a in alerts:
        print(f"  [{a['window_start']:.2f}s - {a['window_end']:.2f}s]  "
              f"id={a['id']}  frames={a['count']}  (baseline≈{a['baseline']:.1f}/window)")


if __name__ == "__main__":
    main()
