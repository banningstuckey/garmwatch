# DNP3 support

GarmWatch's second protocol (Step B on the road to a real product).
DNP3 (IEEE 1815) is the SCADA language of small electric and water
utilities — exactly the sites GarmWatch exists for — so it was the
first language added after Modbus.

## What GarmWatch understands

- **Transport:** DNP3 over TCP or UDP, port 20000.
- **Link layer:** frame start, length, DNP3 source/destination
  addresses, and **every CRC verified** — the header CRC and the
  CRC trailing each block of up to 16 data bytes (CRC-16/DNP).
- **Application layer:** the function code, response vs request,
  unsolicited responses (0x82), and a bounded walk of request
  object headers to spot control objects — group 12 (control
  relay output block, CROB) and group 41 (analog output).

## How detection treats it

DNP3 control commands are the peer of Modbus writes, and the
existing rules treat them that way:

- **Control-class functions** — write, select, operate, direct
  operate (both forms), freeze-and-clear, cold/warm restart,
  stop application, save configuration, enable/disable
  unsolicited responses, delete/set file, activate config — plus
  **any request carrying a control object**, count as writes.
  The *write-from-non-HMI* and *write-outside-pattern* rules fire
  on them exactly as on Modbus writes. The SCADA master is the
  authorized hand; anything else operating an outstation is the
  Oldsmar pattern in a different accent.
- **Restart rule:** a cold or warm restart from anyone is an
  alert (Critical from an unauthorized sender, High even from the
  master — restarts belong in maintenance windows).
- **Broadcast-control rule:** a control command addressed to
  0xFFFF — every outstation at once, with no responses — is
  Critical from anyone, the legitimate master included.
  Indiscriminate is indiscriminate. (A broadcast *read* is fine
  and does not alert.)
- **Bad-checksum rule:** a frame that parses but fails a CRC is
  kept, flagged, and alerted on once per source. Corruption and
  hand-crafted frames (fuzzing) are signals, not silence.
- The **anomaly layer** learns DNP3 function vocabulary per
  device (namespaced from Modbus codes, which reuse the same
  numbers for different verbs), and DNP3 control counts toward
  "a device that never writes."
- **Behavior profiles** record DNP3 poll rhythm, clients, and
  the command mix per outstation (mix keys namespaced +128).
  Register-style value ranges are Modbus-only — DNP3 answers are
  all function 0x81, so there is nothing to pair values with yet.
- **Suspicion** weights the restart (+30) and bad-checksum (+15)
  tags alongside the Modbus-era weights.
- `kind:write` / `kind:read` log queries cover DNP3 commands
  alongside Modbus.

## The lab

The simulated plant gained a DNP3 segment: a **SCADA Master**
(Level 3) polling **North RTU** and **South RTU** (Level 1) with
class-0 reads, and working an output on North RTU about once a
minute — legitimate control from the one authorized device, which
the baseline learns like it learns the HMI's setpoint writes.

The **Rogue DNP3 master** scenario (Rules view) plays the attack:
an unknown device polls North RTU, direct-operates a control
output, then sends a cold restart. Four rules catch it.

## Honest limits

- **Single-frame segments only.** TCP can split a frame across
  segments; a split frame is skipped, not reassembled and not
  guessed at. Small polls and commands — the traffic that matters
  most — fit in one segment in practice.
- **DNP3 Secure Authentication (SAv5)** challenges are not
  parsed; an SA-protected conversation still yields function
  codes, addresses, and control detection from its outer frame.
- **Serial DNP3** is not captured (GarmWatch's sources are
  Ethernet); serial-to-Ethernet terminal servers make most
  serial segments visible as TCP/UDP anyway.
- Point-level profiles (which DNP3 points change, their value
  ranges) are future work; the object walk stops at group
  identification by design.
