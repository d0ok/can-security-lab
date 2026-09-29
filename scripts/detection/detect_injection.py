#!/usr/bin/env python3
"""
Injection detector: unknown-ID allowlisting + adaptive value-plausibility.

Two independent checks:

  1. Unknown ID: any CAN ID seen in the target log that never appears in
     a trusted baseline log is flagged outright. Catches rogue-ECU /
     bus-scanning style injection.

  2. Value jump: for each byte of each KNOWN id, learns the largest
     byte-to-byte delta ever seen in the trusted baseline (its "normal
     envelope" for that byte -- this naturally captures things like a
     signed value wrapping at zero, or a categorical byte's real state
     changes). A target frame is flagged if any byte changes by more
     than that learned envelope (times a safety multiplier). This
     avoids false positives from assuming a fixed signal width/sign
     that doesn't match every ID's real encoding.
"""
import argparse
import sys

sys.path.insert(0, "../common")
from analyze_can import load_log


def unknown_id_check(baseline_df, target_df):
    known_ids = set(baseline_df["can_id"].unique())
    alerts = []
    for can_id, g in target_df.groupby("can_id"):
        if can_id not in known_ids:
            alerts.append({
                "id": f"0x{can_id:03X}",
                "first_seen": g["time"].min(),
                "count": len(g),
            })
    return alerts


def learn_baseline_envelope(baseline_df):
    """Per ID, per byte position: the largest delta ever seen between
    consecutive frames in trusted traffic."""
    envelope = {}
    for can_id, g in baseline_df.groupby("can_id"):
        g = g.sort_values("time")
        payloads = [bytes.fromhex(d) for d in g["data"]]
        width = max(len(p) for p in payloads)
        max_deltas = [0] * width
        for prev, cur in zip(payloads, payloads[1:]):
            for b in range(min(len(prev), len(cur))):
                d = abs(cur[b] - prev[b])
                if d > max_deltas[b]:
                    max_deltas[b] = d
        envelope[can_id] = max_deltas
    return envelope


def value_jump_check(target_df, envelope, multiplier, min_absolute):
    alerts = []
    for can_id, g in target_df.groupby("can_id"):
        if can_id not in envelope:
            continue  # unknown IDs are handled by the other check
        max_deltas = envelope[can_id]
        g = g.sort_values("time").reset_index(drop=True)
        prev = None
        for _, row in g.iterrows():
            cur = bytes.fromhex(row["data"])
            if prev is not None:
                for b in range(min(len(prev), len(cur), len(max_deltas))):
                    d = abs(cur[b] - prev[b])
                    threshold = max(max_deltas[b] * multiplier, min_absolute)
                    if d > threshold:
                        alerts.append({
                            "time": row["time"],
                            "id": f"0x{can_id:03X}",
                            "byte": b,
                            "prev": prev[b],
                            "new": cur[b],
                            "delta": d,
                            "normal_max": max_deltas[b],
                        })
            prev = cur
    return alerts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target_log", help="log to analyze for injected traffic")
    ap.add_argument("--baseline-log", required=True,
                     help="a known-clean log, used to learn normal per-ID/per-byte behavior")
    ap.add_argument("--multiplier", type=float, default=2.0,
                     help="flag byte deltas exceeding this multiple of the "
                          "largest delta ever seen for that byte in the baseline")
    ap.add_argument("--min-absolute", type=int, default=20,
                     help="floor for the threshold, so IDs with a nearly-zero "
                          "baseline envelope don't trigger on tiny natural noise")
    args = ap.parse_args()

    baseline_df = load_log(args.baseline_log)
    target_df = load_log(args.target_log)
    envelope = learn_baseline_envelope(baseline_df)

    id_alerts = unknown_id_check(baseline_df, target_df)
    jump_alerts = value_jump_check(target_df, envelope, args.multiplier, args.min_absolute)

    print(f"=== Unknown ID alerts ({len(id_alerts)}) ===")
    for a in id_alerts:
        print(f"  id={a['id']}  first_seen=t={a['first_seen']:.3f}s  "
              f"frames={a['count']}  <- NOT in baseline allowlist")

    print(f"\n=== Value jump alerts ({len(jump_alerts)}) ===")
    for a in jump_alerts[:50]:
        print(f"  t={a['time']:.3f}s  id={a['id']}  byte={a['byte']}  "
              f"{a['prev']} -> {a['new']}  (Δ={a['delta']}, normal_max≈{a['normal_max']})")
    if len(jump_alerts) > 50:
        print(f"  ... and {len(jump_alerts) - 50} more")

    if not id_alerts and not jump_alerts:
        print("No injection indicators found.")


if __name__ == "__main__":
    main()
