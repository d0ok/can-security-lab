#!/usr/bin/env python3
"""Simulate several ECUs sending periodic can traffic on vcan0."""
import math
import random
import struct
import time

import can

CHANNEL = "vcan0"

def engine_rpm(t):       # 0x100: RPM oscillating 500-3500
    return struct.pack(">H6x", int(2000 + 1500 * math.sin(t / 5)))

def vehicle_speed(t):        # 0x200: speed 20-100 km/h
    return struct.pack(">B7x", int(60 + 10 * math.sin(t / 10 )))

def steering(t):        # 0x300: signed angle, fast changes
    return struct.pack(">h6x", int(300 * math.sin(t * 2)))

def door_status(t):        # 0x400: mostly static, occasionally changes
    return bytes([random.choice([0x00, 0x00, 0x00, 0x01, 0x02, 0x04])]) + bytes(7)

counter = 0
def heartbeat(t):        # 0x500: rolling counter
    global counter
    counter = (counter + 1) % 256
    return bytes([counter]) + bytes(7)

def diag_request(t):        # 0x7DF: random diagnostic-style frame
    return bytes([0x02, 0x01, random.choice([0x0C, 0x0D, 0x05])]) + bytes(5)

# (arbitration ID, period in seconds, payload function)
ECUS = [
    (0x100, 0.020, engine_rpm),
    (0x200, 0.050, vehicle_speed),
    (0x300, 0.010, steering),
    (0x400, 0.500, door_status),
    (0x500, 1.000, heartbeat),
    (0x7DF, 2.000, diag_request),
]

def main():
    bus = can.Bus(interface="socketcan", channel=CHANNEL)
    start = time.monotonic()
    next_send = {arb_id: start for arb_id, _, _ in ECUS}
    print(f"Sending on {CHANNEL}...Ctrl+C to stop")
    try:
        while True:
            now = time.monotonic()
            for arb_id, period, fn in ECUS:
                if now >= next_send[arb_id]:
                    msg = can.Message(arbitration_id=arb_id,
                                      data=fn(now - start),
                                      is_extended_id=False)
                    bus.send(msg)
                    next_send[arb_id] += period
            time.sleep(0.001)
    except KeyboardInterrupt:
        pass
    finally:
        bus.shutdown()

if __name__ == "__main__":
    main() 
