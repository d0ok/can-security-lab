# TARA — Scope, Assets & Damage Scenarios

This Threat Analysis and Risk Assessment (TARA) follows the structure and
terminology of **ISO/SAE 21434** (Road vehicles — Cybersecurity
engineering), adapted for an educational lab built on a virtual CAN bus
(`vcan0`). It is not a certification-grade TARA for a real vehicle
program — it is a demonstration of the TARA methodology, grounded in
attacks actually implemented and tested in this repository.

## 1. Item definition

**Item under analysis:** a simplified in-vehicle CAN bus segment carrying
six message types, modeled after common vehicle domains (powertrain,
chassis, body, diagnostics). This mirrors the traffic simulated by
[`scripts/common/baseline_traffic.py`](../../scripts/common/baseline_traffic.py).

| CAN ID | Signal                | Domain             | Period  |
|--------|------------------------|---------------------|---------|
| 0x100  | Engine RPM             | Powertrain          | 20 ms   |
| 0x200  | Vehicle speed           | Chassis             | 50 ms   |
| 0x300  | Steering angle          | Chassis             | 10 ms   |
| 0x400  | Door lock/unlock status | Body                | 500 ms  |
| 0x500  | ECU heartbeat/counter   | Network management  | 1000 ms |
| 0x7DF  | Diagnostic request (OBD-II functional ID) | Diagnostics | 2000 ms |

**Assumed architecture:** a single, unsegmented CAN bus (no gateway
separating domains), consistent with the flat `vcan0` topology used
in this lab. This is a worst-case-realistic assumption: many older or
cost-constrained vehicle architectures do share a single bus across
these domains, and even segmented architectures often have a
compromised gateway or infotainment unit as an entry point that
achieves the same flat-bus effect.

## 2. Assets

| Asset ID | Asset                                  | Security property at risk |
|----------|------------------------------------------|----------------------------|
| A1       | Engine RPM signal (0x100)                | Integrity, Availability    |
| A2       | Vehicle speed signal (0x200)             | Integrity, Availability    |
| A3       | Steering angle signal (0x300)            | Integrity, Availability    |
| A4       | Door lock status signal (0x400)          | Integrity, Confidentiality |
| A5       | ECU heartbeat / liveness signal (0x500)  | Availability               |
| A6       | Diagnostic request channel (0x7DF)       | Integrity, Availability    |
| A7       | Bus-wide message availability (all IDs)  | Availability               |
| A8       | Logging/monitoring tooling (candump-class tools, any IDS) | Availability |

A8 is included because Step 4's DoS testing found that flood attacks in
this lab measurably impact *log/telemetry capture* even where individual
ECU send/receive timing was largely unaffected. This is itself a
security-relevant asset: an IDS or SOC tool that silently drops data
during an attack is arguably as dangerous as the attack's direct effect.

## 3. Damage scenarios

Damage scenarios describe consequences at the vehicle/operator level,
independent of how they're technically achieved (that link comes later,
in the threat scenarios).

| Damage ID | Damage scenario | Affected assets | Safety / Financial / Operational / Privacy impact |
|-----------|-------------------|-------------------|------------------------------------------------------|
| D1 | Driver or diagnostic tooling receives false RPM/speed/steering data, leading to incorrect decisions or masking a real fault | A1, A2, A3 | Safety (S), Operational (O) |
| D2 | Vehicle doors unlock without driver/owner authorization | A4 | Safety (S), Financial (F) — theft risk |
| D3 | A legitimate ECU appears to go offline (heartbeat starved/spoofed), triggering fail-safe or masking an actual failure | A5 | Safety (S), Operational (O) |
| D4 | Diagnostic session hijacked or spoofed, potentially unlocking privileged ECU functions | A6 | Safety (S), Financial (F) |
| D5 | Bus-wide flooding degrades or delays delivery of time-critical messages | A7 | Safety (S), Operational (O) |
| D6 | Logging/IDS tooling loses visibility into bus traffic during an attack window | A8 | Operational (O) — impairs incident detection/forensics |

Damage scenarios D1, D2, D3 map to the **replay and injection** attacks
(Steps 2–3); D5 and D6 map to the **DoS flood** attack (Step 4), based
on what was actually measured, not assumed.

## References

- ISO/SAE 21434:2021, *Road vehicles — Cybersecurity engineering*
- SAE J3061 (predecessor guidance, useful background)
