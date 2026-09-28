#!/usr/bin/env python3
"""
Naive replay detector.

Flags a frame as a suspected replay if the *exact same payload* for the
same CAN ID repeats faster than that ID's expected minimum period, or
repeats identically more times in a row than is plausible for the signal
it carries. This is intentionally simple (no crypto/counter knowledge —
just what an outside observer sniffing the bus could infer).
"""
import argparse
import sys
sys.path.insert(0, "../common")
from analyze_can import load_log  # reuse the existing parser


def detect(df, min_period_ms, max_repeats):
    alerts = []
    for can_id, g in df.groupby("can_id"):
        g = g.sort_values("time")
        prev_data, prev_time, streak = None, None, 0
        for _, row in g.iterrows():
            if row["data"] == prev_data:
                streak += 1
                dt_ms = (row["time"] - prev_time) * 1000
                if dt_ms < min_period_ms or streak > max_repeats:
                    alerts.append({
                        "time": row["time"],
                        "id": f"0x{can_id:03X}",
                        "data": row["data"],
                        "dt_ms": round(dt_ms, 2),
                        "repeat_streak": streak,
                    })
            else:
                streak = 0
            prev_data, prev_time = row["data"], row["time"]
    return alerts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile")
    ap.add_argument("--min-period-ms", type=float, default=100,
                     help="flag identical payloads arriving faster than this")
    ap.add_argument("--max-repeats", type=int, default=3,
                     help="flag identical payloads repeating more than this many times in a row")
    args = ap.parse_args()

    df = load_log(args.logfile)
    alerts = detect(df, args.min_period_ms, args.max_repeats)

    if not alerts:
        print("No replay indicators found.")
        return

    print(f"{len(alerts)} suspected replay frame(s):\n")
    for a in alerts:
        print(f"  t={a['time']:.3f}s  id={a['id']}  data={a['data']}  "
              f"Δt={a['dt_ms']}ms  streak={a['repeat_streak']}")


if __name__ == "__main__":
    main()
