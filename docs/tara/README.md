# TARA — CAN Security Lab

A Threat Analysis and Risk Assessment, structured per **ISO/SAE 21434**,
for the simplified simulated vehicle CAN bus used throughout this repo.
Every threat scenario here is grounded in an attack actually implemented,
run, and measured in this lab — not a theoretical exercise.

## Documents

1. **[Scope, Assets & Damage Scenarios](01_scope_and_assets.md)**
   Defines the simulated bus (6 CAN IDs modeled on powertrain/chassis/
   body/diagnostic domains), the assets at risk, and the damage
   scenarios that motivate the rest of the analysis.

2. **[Threat Scenarios & Attack Feasibility](02_threat_scenarios_and_feasibility.md)**
   Four STRIDE-classified threats (replay, spoofed-value injection,
   rogue-ID injection, DoS flood), each mapped to the attack script
   that implements it, with ISO/SAE 21434-style feasibility ratings —
   plus an explicit fidelity note on what `vcan0` can and can't
   reproduce compared to a real vehicle bus.

3. **[Risk Matrix & Countermeasures](03_risk_matrix_and_countermeasures.md)**
   Combines impact and feasibility into a risk rating per threat, maps
   each to the detection script that mitigates it (with each
   detector's real limitations disclosed), and lists recommended
   preventive controls that are out of scope for a software-only lab
   (message authentication, gateway segmentation, real-time IDS).

## Key finding

All three spoofing-class threats (replay, value injection, rogue-ID
injection) rate as **Critical risk** — a direct consequence of CAN 2.0's
lack of native message authentication or freshness guarantees, not a
flaw specific to this lab. The DoS flood rates as **High risk**, though
its actual demonstrated impact in this lab is on **logging/monitoring
availability** rather than classic bus-arbitration starvation, which
`vcan0`'s software-loopback nature cannot reproduce (see document 02
for the full explanation).

## Traceability

| Threat | Attack script | Detection script | TARA doc section |
|--------|------------------|----------------------|----------------------|
| T1 Replay | [`replay_attack.py`](../../scripts/attacks/replay_attack.py) | [`detect_replay.py`](../../scripts/detection/detect_replay.py) | Doc 02 §T1, Doc 03 |
| T2 Spoofed injection | [`inject_attack.py --mode spoof`](../../scripts/attacks/inject_attack.py) | [`detect_injection.py`](../../scripts/detection/detect_injection.py) | Doc 02 §T2, Doc 03 |
| T3 Rogue injection | [`inject_attack.py --mode rogue`](../../scripts/attacks/inject_attack.py) | [`detect_injection.py`](../../scripts/detection/detect_injection.py) | Doc 02 §T3, Doc 03 |
| T4 DoS flood | [`dos_attack.py`](../../scripts/attacks/dos_attack.py) | [`detect_dos.py`](../../scripts/detection/detect_dos.py) | Doc 02 §T4, Doc 03 |
