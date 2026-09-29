# TARA — Threat Scenarios & Attack Feasibility

Threat scenarios describe *how* an asset's security property could be
compromised. Each scenario here maps directly to an attack implemented
and tested in this repository, so feasibility ratings are grounded in
what was actually required to execute it — not theoretical estimation.

## STRIDE classification

| Threat ID | Threat scenario | STRIDE category | Related attack script | Assets |
|-----------|-------------------|-------------------|--------------------------|--------|
| T1 | Attacker sniffs a legitimate CAN frame (e.g. door status) and re-transmits it later, out of context, to force a stale/replayed state | Spoofing, Tampering | [`replay_attack.py`](../../scripts/attacks/replay_attack.py) | A4 (also generally A1–A6) |
| T2 | Attacker fabricates a frame on a known/existing ID with an attacker-chosen value, without needing to observe real traffic first | Spoofing, Tampering | [`inject_attack.py --mode spoof`](../../scripts/attacks/inject_attack.py) | A1 (demonstrated), generally A1–A6 |
| T3 | Attacker introduces frames on an ID not used by any legitimate ECU (rogue/compromised node, or bus reconnaissance) | Spoofing, Tampering, Elevation of Privilege | [`inject_attack.py --mode rogue`](../../scripts/attacks/inject_attack.py) | A7 |
| T4 | Attacker floods the bus with high-volume traffic, degrading availability of legitimate messages and/or overwhelming monitoring tools | Denial of Service | [`dos_attack.py`](../../scripts/attacks/dos_attack.py) | A7, A8 |

## Attack potential / feasibility rating (ISO/SAE 21434 style)

ISO/SAE 21434 rates attack feasibility using five factors: **elapsed
time**, **specialist expertise**, **knowledge of the item**, **window
of opportunity**, and **equipment**. Each factor is scored, summed, and
mapped to a feasibility level (High / Medium / Low / Very Low).

Ratings below reflect the *lab conditions actually observed* while
building each attack — for a real vehicle, physical bus access
(equipment/window of opportunity) would typically be harder to obtain,
which is noted separately in the "Real-vehicle adjustment" column.

### T1 — Replay attack

| Factor | Rating | Justification |
|--------|--------|----------------|
| Elapsed time | Low effort (minutes) | Capture + replay logic is ~80 lines of Python; ran successfully on first design iteration |
| Specialist expertise | Layperson–Proficient | Requires basic scripting and `python-can`/`socketcan` familiarity; no cryptography or protocol reverse-engineering needed since CAN has no built-in freshness/authentication |
| Knowledge of the item | Public | No knowledge of payload *meaning* required — frames are replayed verbatim, byte-for-byte |
| Window of opportunity | Moderate | Requires bus access during both the capture and replay phases |
| Equipment | Standard | Any CAN interface + `python-can`; no specialized/bespoke tooling |
| **Feasibility** | **High** | CAN's lack of message authentication or freshness (sequence numbers, timestamps, MACs) makes replay trivial once bus access exists |

### T2 — Spoofed value injection

| Factor | Rating | Justification |
|--------|--------|----------------|
| Elapsed time | Low–Moderate | Requires first determining the target signal's ID and rough encoding (demonstrated separately by the analyzer in the companion `can-sniffer-analyzer` project) |
| Specialist expertise | Proficient | Needs enough reverse-engineering skill to identify which ID/bytes carry the target signal |
| Knowledge of the item | Restricted–Sensitive | Requires payload *format* knowledge (which bytes encode RPM, in what scale) — harder than T1, which needed none |
| Window of opportunity | Moderate | Bus access during the injection window |
| Equipment | Standard | Same as T1 |
| **Feasibility** | **Medium–High** | Achievable with moderate reverse-engineering effort; many production ECUs use simple, undocumented-but-guessable encodings |

### T3 — Rogue ID injection

| Factor | Rating | Justification |
|--------|--------|----------------|
| Elapsed time | Very low | No target-signal knowledge needed at all — literally any unused ID works |
| Specialist expertise | Layperson | Simplest of the three injection/replay attacks to execute |
| Knowledge of the item | Public | None required |
| Window of opportunity | Moderate | Bus access during injection |
| Equipment | Standard | Same as T1/T2 |
| **Feasibility** | **High** | Lowest-effort attack in this lab; primary defense must be network-layer (allowlisting), not obscurity |

### T4 — DoS flood

| Factor | Rating | Justification |
|--------|--------|----------------|
| Elapsed time | Very low | A single loop sending fixed frames; no target knowledge needed |
| Specialist expertise | Layperson | Simplest attack of all four to *implement* |
| Knowledge of the item | Public | None required — arbitrary low-ID flood works regardless of what the bus actually carries |
| Window of opportunity | Moderate | Requires sustained bus access for the flood duration |
| Equipment | Standard | Same as above |
| **Feasibility** | **High** (for the *logging-blindness* impact actually demonstrated); **Low–Medium** (for classic bus-arbitration starvation, which **`vcan0` cannot demonstrate** — see fidelity note below) |

## ⚠️ Simulation fidelity note (important, read before drawing conclusions)

`vcan0` is a **software loopback interface, not a physical CAN bus** —
it has no electrical layer and therefore no bit-level arbitration
contention. Step 4's testing measured this directly and found:

- **No degradation in sender-side timing** of legitimate ECUs during a
  flood (`analyze_dos_impact.py` showed *lower* jitter during the flood
  than baseline, across three tested IDs).
- **No meaningful receiver-side processing lag** for a dedicated
  listener under flood conditions (sub-millisecond throughout).
- **Significant frame loss in userspace logging tooling**: of
  ~2.1M frames sent during a 10s flood, only ~711K (34%) were captured
  in the log, while the kernel netdev interface itself reported zero
  drops — the loss occurs in the logging tool's userspace read/write
  path, not the bus or driver layer.

**Conclusion actually supported by this lab's data:** this simulation
demonstrates DoS against **logging/monitoring availability** (asset A8),
not against ECU-to-ECU message delivery (asset A7) in the way a real
CAN bus's arbitration mechanism would be attacked. On a real vehicle
bus, T4 would also threaten A7 directly via arbitration starvation —
that risk is retained in the risk matrix (next document) as a
real-world consideration, explicitly flagged as **not reproduced by
this lab's technical evidence**, to avoid overclaiming what was
actually tested.
