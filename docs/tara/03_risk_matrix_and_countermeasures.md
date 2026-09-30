# TARA — Risk Matrix & Countermeasures

## Risk determination

ISO/SAE 21434 derives risk from **impact** (severity of the damage
scenario, across Safety/Financial/Operational/Privacy) combined with
**attack feasibility** (from document 02). Impact here is rated
qualitatively (Low/Medium/High/Severe) per damage scenario; feasibility
is carried over from the per-threat ratings already established.

### Impact ratings (per damage scenario, from document 01)

| Damage ID | Damage scenario | Safety | Financial | Operational | Privacy | Overall impact |
|-----------|-------------------|--------|-----------|--------------|---------|------------------|
| D1 | False RPM/speed/steering data | Major | Minor | Moderate | None | **High** |
| D2 | Unauthorized door unlock | Major | Moderate | Minor | None | **High** |
| D3 | Heartbeat spoofed/starved, fail-safe or masked failure | Major | Minor | Moderate | None | **High** |
| D4 | Diagnostic session hijack | Major | Moderate | Moderate | None | **High** |
| D5 | Bus-wide flood degrades message delivery | Major (real bus) / None (this lab's evidence) | Minor | Moderate | None | **High (real bus)** / **Low (this lab)** |
| D6 | Logging/IDS blinded during attack | None (direct) | Minor | Major | None | **Medium–High** |

### Risk matrix

Risk = f(Impact, Feasibility). Using a standard 4×4 qualitative matrix:

| Feasibility ↓ / Impact → | Low | Medium | High | Severe |
|----------------------------|-----|--------|------|--------|
| **Low**                    | Low | Low | Medium | Medium |
| **Medium**                 | Low | Medium | High | High |
| **High**                   | Medium | High | **Critical** | **Critical** |
| **Very High**               | Medium | High | **Critical** | **Critical** |

### Applied risk per threat

| Threat | Feasibility (doc 02) | Damage scenario(s) | Impact | **Risk** |
|--------|------------------------|----------------------|--------|----------|
| T1 — Replay | High | D2 (unauthorized unlock), D1 (stale sensor data) | High | **Critical** |
| T2 — Spoofed value injection | Medium–High | D1 (false sensor data) | High | **Critical** |
| T3 — Rogue ID injection | High | D1, D3 (heartbeat spoof), D4 (diag hijack) | High | **Critical** |
| T4 — DoS flood | High (logging impact, this lab) / Low–Medium (bus starvation, real vehicle, not reproduced here) | D6 (High/Medium), D5 (High on real bus / Low in this lab) | Medium–High | **High** |

All three replay/injection threats land in **Critical**, which is
consistent with the underlying cause: **CAN has no native message
authentication, encryption, or freshness guarantee**, so any node with
bus access can impersonate any other node's messages. This is a
well-known, structural limitation of the CAN 2.0/CAN-FD protocol
itself, not a flaw specific to this lab's simulated ECUs.

## Countermeasures

Countermeasures are split into (a) **detective controls implemented in
this lab** and (b) **preventive controls recommended but out of scope**
for a software-only `vcan0` simulation (they require gateway/ECU-level
changes or cryptographic infrastructure not modeled here).

### Implemented in this lab (detective)

| Threat | Countermeasure | Script | Limitation (honestly stated) |
|--------|-------------------|--------|-------------------------------|
| T1 | Rate-window anomaly detection: flags an ID's frame rate exceeding its own learned baseline rate, catching replay bursts regardless of payload content | [`detect_replay.py`](../../scripts/detection/detect_replay.py) | Requires a trusted baseline capture to learn "normal" rate; a slow, low-volume replay could stay under the detection threshold |
| T2 | Per-byte envelope learning: flags payload byte deltas exceeding the largest change ever observed in a trusted baseline, catching implausible value jumps | [`detect_injection.py`](../../scripts/detection/detect_injection.py) | An attacker who spoofs values *within* the physically plausible range (e.g. RPM=2500 instead of RPM=8000) would evade this detector entirely — it catches implausibility, not falsehood |
| T3 | Allowlist check: flags any CAN ID not present in a trusted baseline capture | [`detect_injection.py`](../../scripts/detection/detect_injection.py) | Requires the allowlist to be genuinely complete; a new legitimate ECU/ID added to a real vehicle would need the allowlist updated, or it would generate false positives |
| T4 | Bus-share dominance detection: flags any ID responsible for a disproportionate fraction of total bus traffic | [`detect_dos.py`](../../scripts/detection/detect_dos.py) | Detects the flood *after* it's already dominating the bus; doesn't prevent the logging-tool packet loss already occurring by the time volume is high enough to flag |

**Important limitation shared by all four detectors:** every one of them
is **passive and offline** — they analyze a captured log after the fact.
None of them can *prevent* an attack in real time, and (per T4's own
finding) a sufficiently intense flood could itself prevent a live/online
version of these detectors from seeing all the traffic they're supposed
to analyze. This is disclosed explicitly rather than glossed over.

### Recommended but not implemented (preventive — require real hardware/architecture beyond this lab's scope)

| Threat(s) | Countermeasure | Why it's out of scope here |
|-----------|-------------------|-------------------------------|
| T1, T2, T3 | Message authentication (e.g. AUTOSAR SecOC — CMAC-based freshness/authentication tags on frames) | Requires ECU-level cryptographic key provisioning and a real AUTOSAR/embedded stack; not meaningfully simulable on `vcan0` |
| T1, T2, T3 | Sender-ID / ECU allowlisting enforced at a gateway (not just detected after capture) | Requires a real or emulated gateway ECU actively filtering traffic, not just a passive log analyzer |
| T3 | Bus segmentation (domain-separated CAN buses with a gateway, so a compromised infotainment/OBD port can't directly inject into safety-critical domains) | Architectural — this lab intentionally used a single flat bus to keep the simulation simple (see doc 01) |
| T4 | Rate limiting / bus-off recovery tuning at the transceiver level | Requires real CAN transceiver hardware behavior, which `vcan0` does not emulate (see fidelity note in doc 02) |
| T4 | Dedicated, isolated logging infrastructure (e.g. hardware CAN logger with its own buffer, decoupled from the flooded bus's own bandwidth) | Hardware procurement/architecture decision, not a software fix |
| All | Intrusion Detection System (IDS) with real-time alerting (vs. this lab's offline analysis scripts) | This lab's detectors are deliberately simple, offline, educational tools — a production IDS would need real-time stream processing, redundant capture paths, and tuned ML/statistical models beyond this lab's scope |

## Summary

| Threat | Risk | Primary implemented mitigation | Residual risk after mitigation |
|--------|------|-----------------------------------|-----------------------------------|
| T1 — Replay | Critical | Rate-anomaly detection | Medium — detection only, no prevention; slow replays may evade |
| T2 — Value injection | Critical | Envelope-based value-plausibility detection | Medium — detection only; in-range spoofing evades |
| T3 — Rogue ID injection | Critical | ID allowlisting | Low–Medium — most reliable detector in this lab, but still detective-only |
| T4 — DoS flood | High | Bus-share dominance detection | Medium — detects the flood, but per T4's own findings, severe floods can blind logging tools before/while being detected |

**Overall conclusion:** this lab demonstrates that a flat, unauthenticated
CAN bus is fundamentally vulnerable to spoofing-class attacks (T1-T3) at
Critical risk, consistent with well-documented, real-world CAN security
research. The detective controls built here provide meaningful
after-the-fact visibility but are not a substitute for the architectural
and cryptographic countermeasures (SecOC, gateway segmentation) used in
production automotive cybersecurity programs.
