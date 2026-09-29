#!/usr/bin/env python3
"""
Measures DoS impact on a RECEIVING node, rather than a sending node.

baseline_traffic.py only sends, so a flood of incoming frames doesn't
contend with its timing (see README/TARA notes on vcan0 fidelity limits).
A more realistic victim is anything that must receive and process every
frame — a gateway ECU, logger, or IDS. This script acts as that receiver:
it reads every frame off the bus (like a naive IDS would), and measures
the delay between a frame's kernel timestamp and when this process
actually got around to handling it. Under a flood, that processing lag
should grow, showing a real, measurable form of denial-of-service against
anything trying to monitor or react to bus traffic in real time.
"""
import argparse
import time

import can


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--channel", default="vcan0")
    ap.add_argument("--duration", type=float, default=20.0)
    ap.add_argument("--target-id", type=lambda x: int(x, 0), default=0x100,
                     help="legitimate ID to report processing lag for")
    ap.add_argument("--report-every", type=int, default=1000,
                     help="print a lag sample every N frames of ANY id processed")
    args = ap.parse_args()

    bus = can.Bus(interface="socketcan", channel=args.channel)
    print(f"[receiver] listening on {args.channel} for {args.duration}s, "
          f"reporting lag on target 0x{args.target_id:03X}...")

    end = time.monotonic() + args.duration
    total = 0
    target_seen = 0
    try:
        while time.monotonic() < end:
            msg = bus.recv(timeout=1.0)
            if msg is None:
                continue
            total += 1
            now = time.time()
            lag_ms = (now - msg.timestamp) * 1000  # kernel rx time vs. our processing time

            if msg.arbitration_id == args.target_id:
                target_seen += 1
                if target_seen % 10 == 0 or lag_ms > 50:
                    print(f"[receiver] t={now:.2f}  target frame #{target_seen}  "
                          f"processing_lag={lag_ms:.2f}ms  (queue depth proxy: "
                          f"{total} total frames processed so far)")
    finally:
        bus.shutdown()

    print(f"\n[receiver] done. Processed {total} total frames, "
          f"{target_seen} of target ID 0x{args.target_id:03X}")


if __name__ == "__main__":
    main()
