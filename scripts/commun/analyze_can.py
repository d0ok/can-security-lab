#!/usr/bin/env python3
"""Parse a candump -L log and print per-ID statistics."""
import argparse
import re
import sys

import pandas as pd

# (1790272016.726065) vcan0 100#0BA9000000000000
LINE_RE = re.compile(
    r"^\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)\s*$"
)


def load_log(path):
    rows, skipped = [], 0
    with open(path) as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                skipped += 1  # RTR, CAN FD (##) or malformed lines
                continue
            ts, iface, arb_id, data = m.groups()
            rows.append((float(ts), iface, int(arb_id, 16), data.upper()))
    if skipped:
        print(f"Warning: skipped {skipped} unparsable lines", file=sys.stderr)
    if not rows:
        sys.exit("No frames parsed. Is this a candump -L log?")

    df = pd.DataFrame(rows, columns=["timestamp", "interface", "can_id", "data"])
    df["time"] = df["timestamp"] - df["timestamp"].iloc[0]  # seconds from start
    df["dlc"] = df["data"].str.len() // 2
    return df


def per_id_stats(df):
    rows = []
    for can_id, g in df.groupby("can_id"):
        dt_ms = g["time"].diff().dropna() * 1000
        span = g["time"].iloc[-1] - g["time"].iloc[0]

        payloads = [bytes.fromhex(d) for d in g["data"]]
        width = max(len(p) for p in payloads)
        varying = [
            i for i in range(width)
            if len({p[i] for p in payloads if len(p) > i}) > 1
        ]

        rows.append({
            "id": f"0x{can_id:03X}",
            "frames": len(g),
            "rate_hz": len(g) / span if span > 0 else float("nan"),
            "period_mean_ms": dt_ms.mean(),
            "period_std_ms": dt_ms.std(),
            "period_min_ms": dt_ms.min(),
            "period_max_ms": dt_ms.max(),
            "unique_payloads": g["data"].nunique(),
            "varying_bytes": ",".join(map(str, varying)) or "-",
        })
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile", help="log created with: candump -L vcan0")
    ap.add_argument("--csv", help="also save the stats table to this CSV file")
    args = ap.parse_args()

    df = load_log(args.logfile)
    duration = df["time"].iloc[-1]
    print(f"Frames: {len(df)}  |  IDs: {df['can_id'].nunique()}  |  "
          f"Duration: {duration:.1f} s  |  Bus load: {len(df)/duration:.0f} frames/s\n")

    stats = per_id_stats(df)
    print(stats.to_string(index=False, float_format=lambda x: f"{x:.2f}"))

    if args.csv:
        stats.to_csv(args.csv, index=False)
        print(f"\nSaved {args.csv}")


if __name__ == "__main__":
    main()
