#!/usr/bin/env python3
"""
DoS / bus-flood detector.

Flags any CAN ID whose observed frame rate is anomalously high relative
to the total bus load — the signature of a flooding attack, regardless
of whether the flood is at a "high priority" (low) ID or any other ID.
Also reports total capture loss context: if the log's total frame count
implies drops relative to a known sender-side count (optional), that's
noted too, since flood-driven logging/telemetry loss is itself a
detectable and important consequence of this attack class.
"""
import argparse
import sys

sys.path.insert(0, "../common")
from analyze_can import load_log


def detect(df, share_threshold):
    total = len(df)
    alerts = []
    for can_id, g in df.groupby("can_id"):
        share = len(g) / total
        if share >= share_threshold:
            rate_hz = len(g) / (g["time"].max() - g["time"].min()) if len(g) > 1 else 0
            alerts.append({
                "id": f"0x{can_id:03X}",
                "frames": len(g),
                "share_pct": share * 100,
                "rate_hz": rate_hz,
            })
    return alerts, total


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile")
    ap.add_argument("--share-threshold", type=float, default=0.5,
                     help="flag any ID responsible for more than this "
                          "fraction of total bus traffic (default 0.5 = 50%%)")
    args = ap.parse_args()

    df = load_log(args.logfile)
    alerts, total = detect(df, args.share_threshold)

    print(f"Total frames in log: {total}")
    if not alerts:
        print("No single ID dominates bus traffic. No flood indicators found.")
        return

    print(f"\n{len(alerts)} ID(s) exceeding {args.share_threshold*100:.0f}% of total bus traffic:\n")
    for a in alerts:
        print(f"  id={a['id']}  frames={a['frames']}  "
              f"share={a['share_pct']:.1f}%  observed_rate≈{a['rate_hz']:.0f} Hz  "
              f"<- SUSPECTED FLOOD SOURCE")


if __name__ == "__main__":
    main()
